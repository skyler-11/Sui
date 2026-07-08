"""
Configuration constants for Manning Simulator
"""

DAYS_A = ["Mon_A", "Tue_A", "Wed_A", "Thu_A", "Fri_A", "Sat_A", "Sun_A"]
DAYS_B = ["Mon_B", "Tue_B", "Wed_B", "Thu_B", "Fri_B", "Sat_B", "Sun_B"]
DAYS = DAYS_A + DAYS_B  # Combined list for 14-day iteration

# Core employee metadata columns carried through parsing, editing, and validation.
EXTRA_COLS = ["Station", "EMP. STATUS", "ID No."]

SHIFT_HRS = {
    "A": 8, "B": 8, "C": 8,
    "AOT": 12, "BOT": 12, "COT": 12,
    "OS5": 9, "RD": 0, "Leave": 0, "": 0, "AWOL": 0,
    "NW": 0,
    "RH": 0, "SPH": 0,
}

SHIFT_TIMES = {
    "A":     {"start": 6,    "end": 14},
    "B":     {"start": 14,   "end": 22},
    "C":     {"start": 22,   "end": 30},
    "AOT":   {"start": 6,    "end": 18},
    "BOT":   {"start": 10,   "end": 22},
    "COT":   {"start": 18,   "end": 30},
    "OS5":   {"start": 8,    "end": 17},
    "RD":    {"start": None, "end": None},
    "Leave": {"start": None, "end": None},
    "AWOL":  {"start": None, "end": None},
    "NW":    {"start": None, "end": None},
    "RH":    {"start": None, "end": None},
    "SPH":   {"start": None, "end": None},
    "":      {"start": None, "end": None},
}

VALID_CODES = ["", "A", "B", "C", "RD", "AOT",
               "BOT", "COT", "Leave", "OS5", "AWOL", "NW",
               "RH", "SPH"]

CODE_MAP = {
    "A":    "A",     "B":    "B",     "C":    "C",
    "AOT":  "AOT",   "BOT":  "BOT",   "COT":  "COT",
    "OS5":  "OS5",   "RD":   "RD",    "LEAVE": "Leave",
    "CS":   "C",     "BS":   "B",     "AS":   "A",
    "AWOL": "AWOL",  "NW":   "NW",
    "RH":   "RH",    "SPH":  "SPH",
}

# ── OT CONSTANTS ──────────────────────────────────────────────────────────────
# OT computation is MATRIX-AWARE. Do NOT apply these constants uniformly.
#
#   6-1 Matrix:
#     Standard shift = 8h (A/B/C).
#     OT shifts = AOT/BOT/COT (12h) → 4h OT per day (12h − 8h baseline).
#     OT_CODES identifies which shift codes constitute overtime for 6-1.
#     OT_HRS_61 = hours above standard baseline per OT shift.
#
#   4-3 Matrix:
#     Standard shift = 12h (AOT/BOT/COT). This is their CONTRACT baseline.
#     OT only triggers on a 5th worked day in a week (beyond 4 standard days).
#     1 OT day = 12h → total = 60h (hits the weekly max exactly).
#     OT_STANDARD_DAYS_43 = standard work days per week before OT triggers.
#     OT_HRS_43 = full shift value of the extra worked day.
#
#   OS5 (9h): EXCLUDED — pending HR/payroll clarification.
# ─────────────────────────────────────────────────────────────────────────────
OT_CODES = {"AOT", "BOT", "COT"}  # codes that are OT in 6-1 matrix
OT_HRS_61 = 4                       # 12h − 8h standard = 4h OT per day
OT_STANDARD_DAYS_43 = 4                       # baseline work days per week in 4-3
OT_HRS_43 = 12                      # full shift value when 5th day worked

# NW (No-Work / plant shutdown) credit for MinWeeklyHoursRule.
# 0 = unpaid shutdown (legacy default, semantically correct for cost-driven NW).
# Set to 8 (DOLE day) when HR treats the shutdown as a paid holiday closure
# so weeks dominated by NW days don't false-fail the weekly minimum.
DEFAULT_NW_CREDIT_HRS = 0

# Keywords for column auto-detection during file parsing
STATION_KW = ["station", "designation"]
STATUS_KW = ["status", "emp"]
ID_KW = ["id no", "id.", "emp no", "empno", "id"]
NAME_KW = ["operator", "name"]
