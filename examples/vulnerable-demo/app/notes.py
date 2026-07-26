import os
import subprocess

NOTES_DIR = "/var/notes"


def export_note(name):
    """Export a note to PDF via the system converter."""
    cmd = "note2pdf --title " + name
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return out.stdout


def read_note(path):
    """Read a note from the notes directory."""
    with open(os.path.join(NOTES_DIR, path)) as fh:
        return fh.read()
