from click.testing import CliRunner

from securevault.cli import cli

PW = "correct horse battery staple 1!"


def run(runner, args, input_text):
    return runner.invoke(cli, args, input=input_text)


def extract_entry_id(list_output: str, service_hint: str) -> str:
    """Pull the entry id out of `list` output, robust to the extra
    "Warning: Password input may be echoed." line getpass emits when stdin
    isn't a real tty (as under CliRunner)."""
    for line in list_output.splitlines():
        if service_hint in line:
            return line.split()[0]
    raise AssertionError(f"no line containing {service_hint!r} in: {list_output!r}")


def init_vault(runner, path, password=PW):
    # init prompts: master password, confirm. A strong password skips the
    # weak-password confirmation prompt.
    result = run(runner, ["init", path], f"{password}\n{password}\n")
    assert result.exit_code == 0, result.output
    return result


def test_init_creates_vault(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    result = init_vault(runner, path)
    assert "Created vault" in result.output
    assert (tmp_path / "vault.dat").exists()


def test_init_refuses_to_overwrite(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    init_vault(runner, path)
    result = run(runner, ["init", path], f"{PW}\n{PW}\n")
    assert result.exit_code != 0
    assert "already exists" in result.output


def test_init_mismatched_confirmation_fails(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    result = run(runner, ["init", path], f"{PW}\nsomething-else\n")
    assert result.exit_code != 0
    assert "did not match" in result.output
    assert not (tmp_path / "vault.dat").exists()


def test_weak_master_password_warns_and_requires_confirmation(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    # "abc" is short and low-entropy; declining the "use it anyway?" prompt aborts.
    result = run(runner, ["init", path], "abc\nabc\nn\n")
    assert result.exit_code != 0
    assert "weak" in result.output.lower()
    assert not (tmp_path / "vault.dat").exists()


def test_weak_master_password_accepted_if_confirmed(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    result = run(runner, ["init", path], "abc\nabc\ny\n")
    assert result.exit_code == 0
    assert (tmp_path / "vault.dat").exists()


def test_add_and_list_never_print_password(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    init_vault(runner, path)

    add_result = run(
        runner,
        ["add", path, "github.com", "alice", "--notes", "work"],
        f"{PW}\nsuper-secret-value\nsuper-secret-value\n",
    )
    assert add_result.exit_code == 0, add_result.output
    assert "super-secret-value" not in add_result.output

    list_result = run(runner, ["list", path], f"{PW}\n")
    assert list_result.exit_code == 0
    assert "github.com" in list_result.output
    assert "alice" in list_result.output
    assert "super-secret-value" not in list_result.output


def test_add_password_mismatch_fails(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    init_vault(runner, path)
    result = run(runner, ["add", path, "svc", "user"], f"{PW}\none\ntwo\n")
    assert result.exit_code != 0
    assert "did not match" in result.output


def test_add_generate_never_prints_password_even_with_generate_flag(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    init_vault(runner, path)
    result = run(runner, ["add", path, "svc", "user", "--generate"], f"{PW}\n")
    assert result.exit_code == 0, result.output
    assert "--show" in result.output  # points the user at `get --show`


def test_get_masks_password_by_default_and_reveals_with_show(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    init_vault(runner, path)
    run(runner, ["add", path, "svc", "user"], f"{PW}\nplaintext-pw\nplaintext-pw\n")

    # Extract the entry id from `list`.
    list_result = run(runner, ["list", path], f"{PW}\n")
    entry_id = extract_entry_id(list_result.output, "svc")

    masked = run(runner, ["get", path, entry_id], f"{PW}\n")
    assert masked.exit_code == 0
    assert "plaintext-pw" not in masked.output
    assert "********" in masked.output

    shown = run(runner, ["get", path, entry_id, "--show"], f"{PW}\n")
    assert shown.exit_code == 0
    assert "plaintext-pw" in shown.output


def test_get_missing_entry_fails_cleanly(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    init_vault(runner, path)
    result = run(runner, ["get", path, "doesnotexist"], f"{PW}\n")
    assert result.exit_code != 0
    assert "no entry" in result.output


def test_wrong_master_password_fails_cleanly(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    init_vault(runner, path)
    result = run(runner, ["list", path], "totally wrong password\n")
    assert result.exit_code != 0
    assert "wrong master password" in result.output.lower()


def test_update_changes_field_without_touching_password(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    init_vault(runner, path)
    run(runner, ["add", path, "svc", "old-user"], f"{PW}\nsecretpw\nsecretpw\n")
    entry_id = extract_entry_id(run(runner, ["list", path], f"{PW}\n").output, "svc")

    result = run(runner, ["update", path, entry_id, "--username", "new-user"], f"{PW}\n")
    assert result.exit_code == 0, result.output

    shown = run(runner, ["get", path, entry_id, "--show"], f"{PW}\n")
    assert "new-user" in shown.output
    assert "secretpw" in shown.output  # unchanged


def test_delete_requires_confirmation_by_default(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    init_vault(runner, path)
    run(runner, ["add", path, "svc", "user"], f"{PW}\npw\npw\n")
    entry_id = extract_entry_id(run(runner, ["list", path], f"{PW}\n").output, "svc")

    declined = run(runner, ["delete", path, entry_id], f"{PW}\nn\n")
    assert declined.exit_code == 0
    assert "Aborted" in declined.output
    still_there = run(runner, ["list", path], f"{PW}\n")
    assert entry_id in still_there.output

    confirmed = run(runner, ["delete", path, entry_id], f"{PW}\ny\n")
    assert confirmed.exit_code == 0
    gone = run(runner, ["list", path], f"{PW}\n")
    assert entry_id not in gone.output


def test_delete_yes_flag_skips_confirmation(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    init_vault(runner, path)
    run(runner, ["add", path, "svc", "user"], f"{PW}\npw\npw\n")
    entry_id = extract_entry_id(run(runner, ["list", path], f"{PW}\n").output, "svc")

    result = run(runner, ["delete", path, entry_id, "--yes"], f"{PW}\n")
    assert result.exit_code == 0
    assert "Deleted" in result.output


def test_passwd_changes_master_password(tmp_path):
    runner = CliRunner()
    path = str(tmp_path / "vault.dat")
    init_vault(runner, path)
    new_pw = "a different strong master password!"
    result = run(runner, ["passwd", path], f"{PW}\n{new_pw}\n{new_pw}\n")
    assert result.exit_code == 0, result.output

    old_fails = run(runner, ["list", path], f"{PW}\n")
    assert old_fails.exit_code != 0

    new_works = run(runner, ["list", path], f"{new_pw}\n")
    assert new_works.exit_code == 0


def test_generate_standalone_prints_password_of_requested_length():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "--length", "16"])
    assert result.exit_code == 0
    assert len(result.output.strip()) == 16


def test_generate_no_categories_fails_cleanly():
    runner = CliRunner()
    result = runner.invoke(
        cli, ["generate", "--no-upper", "--no-lower", "--no-digits", "--no-symbols"]
    )
    assert result.exit_code != 0
    assert "Error" in result.output
