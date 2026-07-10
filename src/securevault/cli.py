"""Command-line interface for securevault.

Drives `repository.VaultRepository` only -- it never touches the file format or
cryptographic primitives directly. Two rules hold everywhere in this module:

1. No secret is ever accepted as a literal command-line argument. A value
   passed as ``--password foo`` would sit in shell history and be visible to
   every other process on the machine via ``ps``. Passwords are always entered
   through `getpass` (no terminal echo) or produced by `passwordgen` (a CSPRNG).
2. `get --show` is the *only* place in this CLI that ever prints a password to
   the terminal, and it is opt-in even there. `add` and `update` never print a
   password, including a freshly generated one -- retrieve it afterwards with
   `get --show`. That keeps the entire plaintext-to-stdout surface auditable at
   a glance.
"""

from __future__ import annotations

import getpass
import os
from typing import NoReturn

import click

from . import passwordgen
from .errors import VaultAuthenticationError, VaultError, VaultFormatError
from .repository import EntryNotFoundError, VaultRepository

# Heuristic only (see passwordgen.estimate_entropy_bits) -- used to warn, never
# to block, a weak master password. Argon2id cannot rescue a guessable password
# (THREAT_MODEL N9); this is the closest a CLI can come to being honest about it.
_WEAK_MASTER_PASSWORD_BITS = 60


def _fail(message: str) -> NoReturn:
    click.echo(f"Error: {message}", err=True)
    raise SystemExit(1)


def _read_master_password(*, confirm: bool) -> bytes:
    password = getpass.getpass("Master password: ")
    if not password:
        _fail("master password must not be empty")
    if confirm:
        again = getpass.getpass("Confirm master password: ")
        if password != again:
            _fail("passwords did not match")
        bits = passwordgen.estimate_entropy_bits(password)
        if bits < _WEAK_MASTER_PASSWORD_BITS:
            click.echo(
                f"Warning: this master password looks weak (~{bits:.0f} estimated bits). "
                f"Argon2id raises the cost of guessing it, but cannot make a guessable "
                f"password unguessable.",
                err=True,
            )
            if not click.confirm("Use it anyway?", default=False):
                _fail("aborted -- choose a stronger master password")
    return password.encode("utf-8")


def _open_repository(path: str) -> VaultRepository:
    if not os.path.exists(path):
        _fail(f"{path} does not exist -- run 'securevault init {path}' first")
    password = getpass.getpass("Master password: ")
    try:
        return VaultRepository.open(path, password.encode("utf-8"))
    except VaultAuthenticationError:
        _fail("wrong master password, or the vault is corrupt or tampered")
    except VaultFormatError as exc:
        _fail(f"not a valid vault file: {exc}")


def _password_gen_options(func):
    func = click.option(
        "--length",
        default=passwordgen.DEFAULT_LENGTH,
        show_default=True,
        type=click.IntRange(passwordgen.MIN_LENGTH, passwordgen.MAX_LENGTH),
        help="Length of a generated password.",
    )(func)
    func = click.option("--upper/--no-upper", default=True, help="Include A-Z.")(func)
    func = click.option("--lower/--no-lower", default=True, help="Include a-z.")(func)
    func = click.option("--digits/--no-digits", default=True, help="Include 0-9.")(func)
    func = click.option("--symbols/--no-symbols", default=True, help="Include punctuation.")(func)
    func = click.option(
        "--exclude-ambiguous", is_flag=True, default=False,
        help="Drop easily-confused characters (I l 1 O 0).",
    )(func)
    return func


def _policy_from_kwargs(kwargs: dict) -> passwordgen.PasswordPolicy:
    return passwordgen.PasswordPolicy(
        length=kwargs["length"],
        use_upper=kwargs["upper"],
        use_lower=kwargs["lower"],
        use_digits=kwargs["digits"],
        use_symbols=kwargs["symbols"],
        exclude_ambiguous=kwargs["exclude_ambiguous"],
    )


def _prompt_entry_password(*, generate: bool, policy: passwordgen.PasswordPolicy) -> str:
    if generate:
        try:
            return passwordgen.generate_password(policy)
        except ValueError as exc:
            _fail(str(exc))
    first = getpass.getpass("Entry password: ")
    second = getpass.getpass("Confirm entry password: ")
    if first != second:
        _fail("passwords did not match")
    if not first:
        _fail("entry password must not be empty")
    return first


@click.group()
@click.version_option(package_name="securevault")
def cli() -> None:
    """A local, offline, encrypted password vault."""


@cli.command()
@click.argument("path", type=click.Path(dir_okay=False))
def init(path: str) -> None:
    """Create a new, empty vault at PATH."""
    if os.path.exists(path):
        _fail(f"{path} already exists")
    password = _read_master_password(confirm=True)
    try:
        VaultRepository.create(path, password).close()
    except VaultError as exc:
        _fail(str(exc))
    click.echo(f"Created vault at {path}")


@cli.command()
@click.argument("path", type=click.Path(dir_okay=False))
@click.argument("service")
@click.argument("username")
@click.option("--notes", default="", help="Optional free-text notes.")
@click.option(
    "--generate/--prompt", "generate", default=False,
    help="Generate the password (default: type it interactively).",
)
@_password_gen_options
def add(path: str, service: str, username: str, notes: str, generate: bool, **gen_kwargs) -> None:
    """Add an entry to the vault at PATH."""
    policy = _policy_from_kwargs(gen_kwargs)
    with _open_repository(path) as repo:
        password = _prompt_entry_password(generate=generate, policy=policy)
        try:
            entry = repo.add_entry(service, username, password, notes)
        except VaultError as exc:
            _fail(str(exc))
    click.echo(f"Added entry {entry.id} ({entry.service} / {entry.username})")
    if generate:
        click.echo(f"Use 'securevault get {path} {entry.id} --show' to view the generated password.")


@cli.command(name="list")
@click.argument("path", type=click.Path(dir_okay=False))
def list_entries(path: str) -> None:
    """List entries in the vault at PATH. Never prints passwords."""
    with _open_repository(path) as repo:
        entries = repo.list_entries()
    if not entries:
        click.echo("(no entries)")
        return
    for entry in sorted(entries, key=lambda e: (e.service.lower(), e.username.lower())):
        note_flag = " [notes]" if entry.notes else ""
        click.echo(f"{entry.id}  {entry.service:<24} {entry.username}{note_flag}")


@cli.command()
@click.argument("path", type=click.Path(dir_okay=False))
@click.argument("entry_id")
@click.option("--show", is_flag=True, default=False, help="Reveal the password (default: masked).")
def get(path: str, entry_id: str, show: bool) -> None:
    """Retrieve a single entry by ID."""
    with _open_repository(path) as repo:
        try:
            entry = repo.get_entry(entry_id)
        except EntryNotFoundError as exc:
            _fail(str(exc))
    click.echo(f"Service:  {entry.service}")
    click.echo(f"Username: {entry.username}")
    click.echo(f"Password: {entry.password if show else '********  (use --show to reveal)'}")
    if entry.notes:
        click.echo(f"Notes:    {entry.notes}")
    click.echo(f"Created:  {entry.created_at}")
    click.echo(f"Updated:  {entry.updated_at}")


@cli.command()
@click.argument("path", type=click.Path(dir_okay=False))
@click.argument("entry_id")
@click.option("--service", default=None, help="New service name.")
@click.option("--username", default=None, help="New username.")
@click.option("--notes", default=None, help="New notes (replaces existing).")
@click.option(
    "--generate/--prompt", "generate", default=None,
    help="Change the password: generate it, or type it interactively. Omit to leave it unchanged.",
)
@_password_gen_options
def update(
    path: str,
    entry_id: str,
    service: str | None,
    username: str | None,
    notes: str | None,
    generate: bool | None,
    **gen_kwargs,
) -> None:
    """Update fields of an existing entry. Only fields you pass are changed."""
    policy = _policy_from_kwargs(gen_kwargs)
    with _open_repository(path) as repo:
        try:
            repo.get_entry(entry_id)
        except EntryNotFoundError as exc:
            _fail(str(exc))
        new_password = None
        if generate is not None:
            new_password = _prompt_entry_password(generate=generate, policy=policy)
        try:
            entry = repo.update_entry(
                entry_id, service=service, username=username, password=new_password, notes=notes
            )
        except VaultError as exc:
            _fail(str(exc))
    click.echo(f"Updated entry {entry.id}")
    if generate:
        click.echo(f"Use 'securevault get {path} {entry.id} --show' to view the generated password.")


@cli.command()
@click.argument("path", type=click.Path(dir_okay=False))
@click.argument("entry_id")
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip the confirmation prompt.")
def delete(path: str, entry_id: str, yes: bool) -> None:
    """Delete an entry from the vault at PATH."""
    with _open_repository(path) as repo:
        try:
            entry = repo.get_entry(entry_id)
        except EntryNotFoundError as exc:
            _fail(str(exc))
        if not yes and not click.confirm(
            f"Delete {entry.service} / {entry.username} ({entry.id})?", default=False
        ):
            click.echo("Aborted.")
            return
        repo.delete_entry(entry_id)
    click.echo(f"Deleted entry {entry_id}")


@cli.command()
@click.argument("path", type=click.Path(dir_okay=False))
def passwd(path: str) -> None:
    """Change the master password for the vault at PATH."""
    with _open_repository(path) as repo:
        new_password = _read_master_password(confirm=True)
        repo.change_master_password(new_password)
    click.echo("Master password changed.")


@cli.command()
@_password_gen_options
def generate(**gen_kwargs) -> None:
    """Print a random password. Does not touch any vault."""
    policy = _policy_from_kwargs(gen_kwargs)
    try:
        click.echo(passwordgen.generate_password(policy))
    except ValueError as exc:
        _fail(str(exc))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
