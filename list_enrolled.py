
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Muestra por consola los usuarios guardados en enrolled_users.csv
"""
import csv, os, sys
from tabulate import tabulate  # pip install tabulate

CSV_FILE = "enrolled_users.csv"

if not os.path.exists(CSV_FILE):
    print("No existe ninguna lista aún.")
    sys.exit(0)

with open(CSV_FILE, newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

print(tabulate(rows, headers="keys", tablefmt="github"))
print(f"\nTotal usuarios: {len(rows)}")
