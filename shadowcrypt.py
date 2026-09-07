from PIL import Image, UnidentifiedImageError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import struct
import getpass
import hashlib
import random

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box


console = Console()

PBKDF2_ITERATIONS = 200_000
SALT_LEN = 16
NONCE_LEN = 12
HEADER_BITS = 32
PER_MESSAGE_OVERHEAD_BYTES = 4 + SALT_LEN + NONCE_LEN  # length + salt + nonce (tag is inside ciphertext)


# ============================================================
# CRYPTO / STEGO CORE  (unchanged behavior from previous version)
# ============================================================

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_position_seed(password: str) -> int:
    digest = hashlib.sha256(("STEGO-ORDER::" + password).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def get_embedding_order(capacity: int, seed: int):
    rng = random.Random(seed)
    order = list(range(capacity))
    rng.shuffle(order)
    return order


def text_to_bits(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def bits_to_bytes(bits: str) -> bytes:
    return bytes(
        int(bits[i:i + 8], 2)
        for i in range(0, len(bits), 8)
        if len(bits[i:i + 8]) == 8
    )


def hide_message(input_file, output_file, message, password):
    image = Image.open(input_file).convert("RGB")
    pixels = list(image.getdata())
    flat = [c for pixel in pixels for c in pixel]
    capacity = len(flat)

    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    nonce = os.urandom(NONCE_LEN)

    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, message.encode("utf-8"), None)

    payload = struct.pack(">I", len(ciphertext)) + salt + nonce + ciphertext
    bits = text_to_bits(payload)

    if len(bits) > capacity:
        raise ValueError("Message is too large for this image.")

    order = get_embedding_order(capacity, derive_position_seed(password))
    jitter = random.Random()

    for i, bit in enumerate(bits):
        pos = order[i]
        current_val = flat[pos]
        desired_bit = int(bit)

        if (current_val & 1) != desired_bit:
            if current_val == 0:
                flat[pos] = 1
            elif current_val == 255:
                flat[pos] = 254
            else:
                flat[pos] = current_val + jitter.choice((-1, 1))

    new_pixels = [tuple(flat[i:i + 3]) for i in range(0, len(flat), 3)]
    image.putdata(new_pixels)
    image.save(output_file, "PNG")


def extract_message(input_file, password):
    image = Image.open(input_file).convert("RGB")
    pixels = list(image.getdata())
    flat = [c for pixel in pixels for c in pixel]
    capacity = len(flat)

    order = get_embedding_order(capacity, derive_position_seed(password))

    def read_bits(start, count):
        return "".join(str(flat[order[i]] & 1) for i in range(start, start + count))

    header_bits = read_bits(0, HEADER_BITS)
    header = bits_to_bytes(header_bits)
    if len(header) != 4:
        raise ValueError("Invalid or corrupted image.")

    ciphertext_length = struct.unpack(">I", header)[0]
    total_needed = HEADER_BITS + (SALT_LEN + NONCE_LEN + ciphertext_length) * 8

    if total_needed > capacity:
        raise ValueError("Image does not contain enough data.")

    payload_bits = read_bits(HEADER_BITS, total_needed - HEADER_BITS)
    payload = bits_to_bytes(payload_bits)

    salt = payload[:SALT_LEN]
    nonce = payload[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = payload[SALT_LEN + NONCE_LEN:]

    key = derive_key(password, salt)
    aes = AESGCM(key)
    try:
        plaintext = aes.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed. Wrong password or corrupted image.")

    return plaintext.decode("utf-8")


def get_image_capacity_bytes(input_file) -> tuple:
    """Returns (image, capacity_bits, max_message_bytes)."""
    image = Image.open(input_file).convert("RGB")
    width, height = image.size
    capacity_bits = width * height * 3
    usable_bits = capacity_bits - HEADER_BITS - (PER_MESSAGE_OVERHEAD_BYTES * 8)
    max_message_bytes = max(usable_bits // 8, 0)
    return image, width, height, capacity_bits, max_message_bytes


# ============================================================
# RICH UI
# ============================================================

def print_banner():
    console.print(
        Panel.fit(
            "[bold cyan]AES-256-GCM STEGO TOOL[/bold cyan]\n"
            "[dim]encrypted • scattered LSB matching • password-derived ordering[/dim]",
            border_style="cyan",
            box=box.DOUBLE,
        )
    )


def print_menu():
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_row("[bold green]1[/bold green]", "Encrypt / Hide message")
    table.add_row("[bold green]2[/bold green]", "Decrypt / Extract message")
    table.add_row("[bold green]3[/bold green]", "Check image capacity")
    table.add_row("[bold red]4[/bold red]", "Exit")
    console.print(table)


def get_confirmed_password() -> str:
    while True:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password == confirm:
            return password
        console.print("[red]Passwords do not match. Try again.[/red]")


def encrypt_mode():
    console.print(Panel("[bold]Encrypt[/bold]", border_style="green", box=box.ROUNDED))

    image_file = Prompt.ask("Image file")
    output_file = Prompt.ask("Output image name")
    if not output_file.lower().endswith(".png"):
        output_file += ".png"

    message = Prompt.ask("Message")
    password = get_confirmed_password()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Encrypting and embedding...", total=None)
        hide_message(image_file, output_file, message, password)

    console.print(f"[bold green]✓ Success.[/bold green] Output saved to [cyan]{output_file}[/cyan]")


def decrypt_mode():
    console.print(Panel("[bold]Decrypt[/bold]", border_style="magenta", box=box.ROUNDED))

    image_file = Prompt.ask("Stego image")
    password = getpass.getpass("Password: ")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Extracting and decrypting...", total=None)
        message = extract_message(image_file, password)

    console.print(Panel(message, title="[bold]Hidden message[/bold]", border_style="magenta", box=box.ROUNDED))


def capacity_mode():
    console.print(Panel("[bold]Capacity check[/bold]", border_style="yellow", box=box.ROUNDED))

    image_file = Prompt.ask("Image file")
    _, width, height, capacity_bits, max_message_bytes = get_image_capacity_bytes(image_file)

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Dimensions", f"{width} x {height}")
    table.add_row("Raw channel capacity", f"{capacity_bits:,} bits")
    table.add_row("Fixed overhead", f"{PER_MESSAGE_OVERHEAD_BYTES} bytes (salt+nonce+length)")
    table.add_row("Max message size", f"[bold green]{max_message_bytes:,} bytes[/bold green] (~{max_message_bytes} ASCII chars)")

    console.print(table)


def run_action(choice: str) -> bool:
    try:
        if choice == "1":
            encrypt_mode()
        elif choice == "2":
            decrypt_mode()
        elif choice == "3":
            capacity_mode()
        elif choice == "4":
            console.print("[bold]Goodbye.[/bold]")
            return False
        else:
            console.print("[red]Invalid option.[/red]")

    except FileNotFoundError:
        console.print("[red]Error: Image file not found. Check the path and try again.[/red]")

    except UnidentifiedImageError:
        console.print("[red]Error: That file isn't a readable image (or is corrupted).[/red]")

    except PermissionError:
        console.print("[red]Error: Permission denied reading or writing that file.[/red]")

    except ValueError as error:
        console.print(f"[red]Error: {error}[/red]")

    except Exception as error:
        console.print(f"[red]Unexpected error: {error}[/red]")

    return True


def main():
    print_banner()

    while True:
        console.print()
        print_menu()
        choice = Prompt.ask("\n[bold]Choose[/bold]", choices=["1", "2", "3", "4"], show_choices=False)

        if not run_action(choice):
            break


if __name__ == "__main__":
    main()
