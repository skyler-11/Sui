"""Validation rules for Manning Simulator (matrix-aware: 6-1 and 4-3 patterns)."""

from __future__ import annotations

from typing import Optional, Tuple
import pandas as pd

from app.core.config import DAYS, DAYS_A, DAYS_B, SHIFT_TIMES, VALID_CODES
from app.core.logging import get_logger

logger = get_logger("forge.rules")


# ── MATRIX DETECTION ─────────────────────────────────────────────────────────

WEEKEND_RDS = {"Sat_A", "Sun_A", "Sat_B", "Sun_B"}
MON_THU = {"Mon_A", "Tue_A", "Wed_A", "Thu_A",
           "Mon_B", "Tue_B", "Wed_B", "Thu_B"}
FRIDAYS = {"Fri_A", "Fri_B"}
WEEKDAYS = MON_THU | FRIDAYS
REST_EQUIV = {"RD", "LEAVE", "RH", "SPH", "NW"}

# Shift-code signatures used to classify the work pattern. AOT/BOT/COT are 12h
# shifts native to the 4-3 matrix; A/B/C/OS5 are 8-9h shifts native to 6-1/5-2.
WORK_43 = {"AOT", "BOT", "COT"}
WORK_61 = {"A", "B", "C", "OS5"}


def detect_matrix(row: pd.Series) -> str:
    """
    Classify the row's matrix from the shift codes actually scheduled.

    Precedence (most specific → most generic):
      1. Only 12h shifts (AOT/BOT/COT) present → 4-3.
      2. Only 8-9h shifts (A/B/C/OS5) present → 6-1, or 5-2 when both
         weekends are full rest and no weekday RD exists.
      3. Mixed 12h + 8-9h shifts → 4-3 if **either** signal holds:
           • count_43 > count_61 (AOT-dominant pattern, e.g. EMP_10-style
             5 AOT + 1 RD + 1 A per week — clear 4-3 with OT extension
             and 1 substitute day).
           • literal RD count ≥ 4 over 14 days (compressed-rest pattern
             of 4-3 with one OT-day swap, e.g. EMP_11-style 5 AOT + 5 A
             + 4 RD).
         Either alone is sufficient. Counting only literal RD (not
         LEAVE/RH/SPH/NW) avoids over-triggering on incidental absences
         that don't reflect contract structure. Tie majority + RD < 4 →
         6-1 (matches HR's `AOT,AOT,AOT,A,A,A,RD` hypothetical).
      4. No work shifts at all (full leave/RD/NW record) → legacy
         rest-equivalent fallback (preserves prior behavior).

    Looking at the actual shifts first prevents an 8h-shift employee from
    being flipped to 4-3 just because an unrelated shutdown (NW) or leave
    cluster pushed the rest-equivalent count above 6 — the original
    structural bug behind EMP_1 / EMP_3 / EMP_4 false-fails.
    """
    def code(d):
        return str(row.get(d, "")).strip().upper()

    codes = [code(d) for d in DAYS]
    has_43 = any(c in WORK_43 for c in codes)
    has_61 = any(c in WORK_61 for c in codes)

    if has_43 and not has_61:
        return "4-3"

    if has_61 and not has_43:
        weekend_rest = all(code(d) in REST_EQUIV for d in WEEKEND_RDS)
        weekday_rd = any(code(d) == "RD" for d in WEEKDAYS)
        return "5-2" if (weekend_rest and not weekday_rd) else "6-1"

    if has_43 and has_61:
        count_43 = sum(1 for c in codes if c in WORK_43)
        count_61 = sum(1 for c in codes if c in WORK_61)
        rd_literal = sum(1 for c in codes if c == "RD")
        if count_43 > count_61 or rd_literal >= 4:
            return "4-3"
        return "6-1"

    rd_count = sum(1 for c in codes if c in REST_EQUIV)
    if rd_count >= 6:
        return "4-3"
    weekend_rest = all(code(d) in REST_EQUIV for d in WEEKEND_RDS)
    weekday_rd = any(code(d) == "RD" for d in WEEKDAYS)
    if weekend_rest and not weekday_rd:
        return "5-2"
    return "6-1"


# ── SHIFT GAP HELPER ──────────────────────────────────────────────────────────

def _rest_gap(s1: str, s2: str) -> Optional[float]:
    """
    Calculates rest hours between consecutive shifts.
    Returns None if either shift has no defined end/start time (RD, Leave, etc.)
    """
    t = SHIFT_TIMES.get(s1, {})
    n = SHIFT_TIMES.get(s2, {})
    if t.get("end") is None or n.get("start") is None:
        return None
    return (24 + n["start"]) - t["end"]


# ── BASE CLASS ────────────────────────────────────────────────────────────────

class ValidationRule:
    def __init__(self, key: str, name: str, default_active: bool = True):
        self.key = key
        self.name = name
        self.default_active = default_active

    def evaluate_df(
        self,
        df: pd.DataFrame,
        config: dict,
    ) -> Tuple[pd.Series, pd.Series, Optional[pd.Series], Optional[pd.Series]]:
        """
        Returns (passed, message, global_violations, daily_violations).
        All series must be aligned to df.index.
        """
        raise NotImplementedError

    def _log_result(self, passed: pd.Series) -> None:
        total = len(passed)
        n_pass = int(passed.sum())
        logger.debug("Rule [%s] — %d/%d passed, %d failed",
                     self.name, n_pass, total, total - n_pass)


# ── RULES ─────────────────────────────────────────────────────────────────────

class MaxDailyHoursRule(ValidationRule):
    """
    Validates per-day hours against matrix-specific min/max bounds.
      4-3 Matrix: exactly 12h per worked day (AOT/BOT/COT only)
      6-1 Matrix: 8h–12h per worked day
    """

    def __init__(self):
        super().__init__("max_day", "Daily Hours Check")

    def evaluate_df(self, df, config):
        logger.debug("Rule [%s] starting — %d rows", self.name, len(df))

        def check_daily(row):
            matrix = row.get("_matrix", "6-1")
            day_v = []
            if matrix == "5-2":
                for day in DAYS:
                    hrs = row.get(f"{day}_hrs", 0)
                    if hrs <= 0:
                        continue
                    if day in MON_THU and hrs != 9:
                        day_v.append(f"{day}({hrs}h, expected 9h)")
                    elif day in FRIDAYS and hrs != 8:
                        day_v.append(f"{day}({hrs}h, expected 8h)")
                    elif day in WEEKEND_RDS:
                        day_v.append(f"{day}({hrs}h, expected RD)")
            else:
                min_hrs = 12 if matrix == "4-3" else 8
                max_hrs = 12
                for day in DAYS:
                    hrs = row.get(f"{day}_hrs", 0)
                    if hrs > 0 and (hrs < min_hrs or hrs > max_hrs):
                        day_v.append(f"{day}({hrs}h)")
            if day_v:
                return False, "❌ " + ", ".join(day_v), day_v
            return True, "✅", []

        results = df.apply(check_daily, axis=1, result_type="expand")
        passed = results[0].astype(bool)
        msg = results[1]
        dv = results[2]
        self._log_result(passed)
        return passed, msg, None, dv


class MaxWeeklyHoursRule(ValidationRule):
    """
    VECTORIZED. Both weeks must not exceed max_week hours.

    Threshold is fully user-configured via the sidebar Max Weekly Hours
    input (default 60). Applies uniformly across all matrices (4-3, 6-1,
    5-2). Matrix-specific structural constraints (consecutive RDs, daily
    hours, etc.) are enforced by their own dedicated rules.
    """

    def __init__(self):
        super().__init__("max_week", "Maximum Weekly Hours")

    def evaluate_df(self, df, config):
        cfg_max = config.get("max_week", 60)

        def _check(r):
            parts = []
            if r["Total Hrs A"] > cfg_max:
                parts.append(f"Wk A: {r['Total Hrs A']}h")
            if r["Total Hrs B"] > cfg_max:
                parts.append(f"Wk B: {r['Total Hrs B']}h")
            if parts:
                return False, "❌ " + ", ".join(parts) + f" exceeds max {cfg_max}h"
            return True, "✅"

        results = df.apply(_check, axis=1, result_type="expand")
        passed = results[0].astype(bool)
        msg = results[1]

        self._log_result(passed)
        return passed, msg, None, None


class MaxRolling7DayHoursRule(ValidationRule):
    """
    Rolling 7-day window cap. Catches cross-week excess that per-week
    MaxWeeklyHoursRule misses (e.g., 6 consecutive 12h days spanning
    Wk A → Wk B = 72h in any 7-day window).

    Iterates 8 windows of length 7 across the 14-day matrix
    (start indices 0..7). Flags any window whose summed hours exceed
    config["max_rolling_7d"].
    """

    def __init__(self):
        super().__init__("max_rolling_7d", "Max Rolling 7-Day Hours")

    def evaluate_df(self, df, config):
        cap = config.get("max_rolling_7d", 60)

        def check_window(row):
            hrs = [row.get(f"{d}_hrs", 0) for d in DAYS]
            worst_total = 0
            worst_start = 0
            for i in range(len(DAYS) - 6):
                total = sum(hrs[i:i + 7])
                if total > worst_total:
                    worst_total = total
                    worst_start = i
            if worst_total > cap:
                window_label = f"{DAYS[worst_start]}→{DAYS[worst_start + 6]}"
                return False, f"❌ {worst_total}h in {window_label} (max {cap}h rolling 7d)"
            return True, "✅"

        results = df.apply(check_window, axis=1, result_type="expand")
        passed = results[0].astype(bool)
        msg = results[1]
        self._log_result(passed)
        return passed, msg, None, None


class MinRestDaysRule(ValidationRule):
    """
    AWOL days intentionally do NOT count as rest — employees on AWOL are
    considered working-absent, not resting. LEAVE / RH / SPH / NW all
    count toward effective rest days (paid holidays, leave, and company-
    initiated shutdowns are legitimate non-work days).

    4-3 RD requirement is OT-aware: baseline = 3 RDs/wk, but when the
    employee takes an OT day (worked 5+ days that week → OT Hrs > 0),
    one RD is legitimately consumed → 2 RDs/wk is HR-acceptable. DOLE
    compliance is preserved by MaxWeeklyHoursRule (60h cap) and
    ConsecutiveWorkDaysRule (5-day limit). The OT Hrs columns are
    computed in app/utils.py before rules run.
    """

    REST_EXTRA = {"LEAVE", "RH", "SPH", "NW"}

    def __init__(self):
        super().__init__("min_rd", "Minimum Rest Days")

    def evaluate_df(self, df, config):

        def check_rd(row):
            matrix = row.get("_matrix", "6-1")

            if matrix == "4-3":
                ot_a = row.get("OT Hrs A", 0)
                ot_b = row.get("OT Hrs B", 0)
                min_rd_a = 2 if ot_a > 0 else 3
                min_rd_b = 2 if ot_b > 0 else 3
            elif matrix == "5-2":
                min_rd_a = min_rd_b = 2
            else:  # 6-1
                min_rd_a = min_rd_b = 1

            extra_A = sum(1 for d in DAYS_A if str(
                row.get(d, "")).strip().upper() in self.REST_EXTRA)
            extra_B = sum(1 for d in DAYS_B if str(
                row.get(d, "")).strip().upper() in self.REST_EXTRA)

            eff_rd_A = row.get("rd_count_A", 0) + extra_A
            eff_rd_B = row.get("rd_count_B", 0) + extra_B

            if eff_rd_A >= min_rd_a and eff_rd_B >= min_rd_b:
                return True, "✅"

            parts = []
            if eff_rd_A < min_rd_a:
                parts.append(f"Wk A: {eff_rd_A} RDs (need {min_rd_a})")
            if eff_rd_B < min_rd_b:
                parts.append(f"Wk B: {eff_rd_B} RDs (need {min_rd_b})")
            return False, "❌ " + ", ".join(parts)

        results = df.apply(check_rd, axis=1, result_type="expand")
        passed = results[0].astype(bool)
        msg = results[1]
        self._log_result(passed)
        return passed, msg, None, None


class BrokenRestDayRule(ValidationRule):
    """
    4-3 / 5-2: Rest Days within each week must be consecutive.
    6-1: auto-pass (only 1 RD/week).
    """

    def __init__(self):
        super().__init__("broken_rd", "Consecutive Rest Days")

    def evaluate_df(self, df, config):

        def check_broken(row):
            if row.get("_matrix", "6-1") not in ("4-3", "5-2"):
                return True, "✅"

            def count_blocks(days_list):
                blocks, in_rd = 0, False
                for d in days_list:
                    cell = str(row.get(d, "")).strip().upper()
                    # LEAVE / RH / SPH / NW are transparent — they don't
                    # break an RD streak (paid holiday between two RDs is
                    # still rest) but they don't open a new block either.
                    if cell in {"LEAVE", "RH", "SPH", "NW"}:
                        continue
                    is_rd = cell == "RD"
                    if is_rd and not in_rd:
                        blocks += 1
                        in_rd = True
                    elif not is_rd:
                        in_rd = False
                return blocks

            broken = []
            if count_blocks(DAYS_A) > 1:
                broken.append("Wk A")
            if count_blocks(DAYS_B) > 1:
                broken.append("Wk B")

            if broken:
                return False, f"❌ Broken Rest Days in {' & '.join(broken)} (Must be consecutive)"
            return True, "✅"

        results = df.apply(check_broken, axis=1, result_type="expand")
        passed = results[0].astype(bool)
        msg = results[1]
        self._log_result(passed)
        return passed, msg, None, None


class ConsecutiveWorkDaysRule(ValidationRule):
    """
    Max consecutive work days:
      4-3 Matrix → 5 days
      6-1 Matrix → 6 days
    """

    def __init__(self):
        super().__init__("max_consecutive", "Consecutive Work Days")

    def evaluate_df(self, df, config):
        logger.debug("Rule [%s] starting", self.name)

        def check_consecutive(row):
            matrix = row.get("_matrix", "6-1")
            limit = 6 if matrix == "6-1" else 5
            work_days = [row.get(f"{day}_hrs", 0) > 0 for day in DAYS]

            max_streak = cur_streak = 0
            max_start = cur_start = 0

            for i, is_work in enumerate(work_days):
                if is_work:
                    if cur_streak == 0:
                        cur_start = i
                    cur_streak += 1
                    if cur_streak > max_streak:
                        max_streak = cur_streak
                        max_start = cur_start
                else:
                    cur_streak = 0

            if max_streak > limit:
                max_end = max_start + max_streak - 1
                spans_a = max_start <= 6
                spans_b = max_end >= 7
                if spans_a and spans_b:
                    wk_label = "Wk A & Wk B (cross-week)"
                elif spans_a:
                    wk_label = "Wk A"
                else:
                    wk_label = "Wk B"
                return False, f"❌ {max_streak} consecutive work days in {wk_label} (Max {limit})"
            return True, "✅"

        results = df.apply(check_consecutive, axis=1, result_type="expand")
        passed = results[0].astype(bool)
        msg = results[1]
        self._log_result(passed)
        return passed, msg, None, None


class ShiftGapRule(ValidationRule):
    """Detects insufficient rest between consecutive shifts."""

    def __init__(self):
        super().__init__("shift_gap", "Mandatory Shift Gap")

    def evaluate_df(self, df, config):
        logger.debug("Rule [%s] starting — %d rows", self.name, len(df))

        def check_gap(row):
            shifts = [str(row.get(d, "")).strip() for d in DAYS]
            gap_v = []
            for i in range(len(DAYS) - 1):
                g = _rest_gap(shifts[i], shifts[i + 1])
                if g is not None and g < 8:
                    gap_v.append(
                        f"{DAYS[i]}→{DAYS[i+1]} "
                        f"({shifts[i]}→{shifts[i+1]}, {g:.0f}h gap, min 8h)"
                    )
            if gap_v:
                return False, "❌ " + "; ".join(gap_v), gap_v
            return True, "✅", []

        results = df.apply(check_gap, axis=1, result_type="expand")
        passed = results[0].astype(bool)
        msg = results[1]
        gv = results[2]
        self._log_result(passed)
        return passed, msg, gv, None


class MinWeeklyHoursRule(ValidationRule):
    """
    Both weeks must meet or exceed min_week hours.

    LEAVE / RH / SPH credited at matrix-appropriate shift length:
      4-3  → 12h per day
      6-1  → 8h per day
      5-2  → 9h Mon-Thu, 8h Fri (per-day basis, weekend gives no credit
             since weekend is structural rest)

    NW (plant shutdown / no inventory) is rest-equivalent for MinRestDays,
    BrokenRestDay, and matrix detection. By default it credits 0h
    (unpaid shutdown). HR can raise the credit via config["nw_credit_hrs"]
    (sidebar) for paid-holiday-closure weeks so they stop false-failing
    the weekly minimum. Applied flat across matrices on purpose — HR sets
    it once per session.

    AWOL is never credited (unjustified absence).

    Threshold is fully user-configured via the sidebar Min Weekly Hours
    input (default 48). 5-2 uses a fixed structural floor of 44h when the
    sidebar is at its default — switches to the user's value otherwise.
    """

    CRED_CODES = {"LEAVE", "RH", "SPH"}

    def __init__(self):
        super().__init__("min_week", "Minimum Weekly Hours")

    def evaluate_df(self, df, config):
        cfg_min = config.get("min_week", 48)
        nw_credit = config.get("nw_credit_hrs", 0)

        def check_min(row):
            matrix = row.get("_matrix", "6-1")

            if matrix == "5-2":
                SIDEBAR_DEFAULT = 48
                LEGACY_5_2_DEFAULT = 44
                min_week = cfg_min if cfg_min != SIDEBAR_DEFAULT else LEGACY_5_2_DEFAULT

                def leave_credit(days):
                    total = 0
                    for d in days:
                        if str(row.get(d, "")).strip().upper() not in self.CRED_CODES:
                            continue
                        total += 9 if d in MON_THU else (8 if d in FRIDAYS else 0)
                    return total

                nw_A = nw_credit * sum(1 for d in DAYS_A if str(
                    row.get(d, "")).strip().upper() == "NW") if nw_credit > 0 else 0
                nw_B = nw_credit * sum(1 for d in DAYS_B if str(
                    row.get(d, "")).strip().upper() == "NW") if nw_credit > 0 else 0
                eff_A = row.get("Total Hrs A", 0) + leave_credit(DAYS_A) + nw_A
                eff_B = row.get("Total Hrs B", 0) + leave_credit(DAYS_B) + nw_B
            else:
                min_week = cfg_min
                credit = 12 if matrix == "4-3" else 8
                cred_A = sum(1 for d in DAYS_A if str(
                    row.get(d, "")).strip().upper() in self.CRED_CODES)
                cred_B = sum(1 for d in DAYS_B if str(
                    row.get(d, "")).strip().upper() in self.CRED_CODES)
                nw_A = nw_credit * sum(1 for d in DAYS_A if str(
                    row.get(d, "")).strip().upper() == "NW") if nw_credit > 0 else 0
                nw_B = nw_credit * sum(1 for d in DAYS_B if str(
                    row.get(d, "")).strip().upper() == "NW") if nw_credit > 0 else 0
                eff_A = row.get("Total Hrs A", 0) + (cred_A * credit) + nw_A
                eff_B = row.get("Total Hrs B", 0) + (cred_B * credit) + nw_B

            if eff_A >= min_week and eff_B >= min_week:
                return True, "✅"

            parts = []
            if eff_A < min_week:
                parts.append(f"Wk A: {eff_A}h")
            if eff_B < min_week:
                parts.append(f"Wk B: {eff_B}h")
            return False, "❌ " + ", ".join(parts) + f" below min {min_week}h"

        results = df.apply(check_min, axis=1, result_type="expand")
        passed = results[0].astype(bool)
        msg = results[1]
        self._log_result(passed)
        return passed, msg, None, None


class HolidayPayFlagRule(ValidationRule):
    """DOLE Art. 94: annotate RH (200%) and SPH (130%) days for payroll. Always passes."""

    def __init__(self):
        super().__init__("holiday_pay", "Holiday Pay Flag")

    def evaluate_df(self, df, config):

        def check_holidays(row):
            rh = [d for d in DAYS if str(row.get(d, "")).strip().upper() == "RH"]
            sph = [d for d in DAYS if str(row.get(d, "")).strip().upper() == "SPH"]
            parts = []
            if rh:
                parts.append(f"RH 200%: {', '.join(rh)}")
            if sph:
                parts.append(f"SPH 130%: {', '.join(sph)}")
            if parts:
                return True, "ℹ️ " + "; ".join(parts)
            return True, "✅"

        results = df.apply(check_holidays, axis=1, result_type="expand")
        passed = results[0].astype(bool)
        msg = results[1]
        self._log_result(passed)
        return passed, msg, None, None


class ValidShiftCodesRule(ValidationRule):
    """
    Flags any non-empty cell containing an unrecognized shift code.
    Empty cells ("") are allowed — they mean "not scheduled".
    """

    def __init__(self):
        super().__init__("valid_codes", "Valid Shift Codes")

    def evaluate_df(self, df, config):
        logger.debug("Rule [%s] starting — %d rows", self.name, len(df))
        valid_upper = {str(v).strip().upper() for v in VALID_CODES}

        def check_codes(row):
            invalid = [
                f"{day}({row.get(day, '')})"
                for day in DAYS
                if str(row.get(day, "")).strip()
                and str(row.get(day, "")).strip().upper() not in valid_upper
            ]
            if invalid:
                return False, "❌ Invalid: " + ", ".join(invalid)
            return True, "✅"

        results = df.apply(check_codes, axis=1, result_type="expand")
        passed = results[0].astype(bool)
        msg = results[1]
        self._log_result(passed)
        return passed, msg, None, None


# ── REGISTRY ─────────────────────────────────────────────────────────────────

AVAILABLE_RULES = [
    MaxDailyHoursRule(),
    MaxWeeklyHoursRule(),
    MaxRolling7DayHoursRule(),
    MinWeeklyHoursRule(),
    ConsecutiveWorkDaysRule(),
    ValidShiftCodesRule(),
    MinRestDaysRule(),
    BrokenRestDayRule(),
    ShiftGapRule(),
    HolidayPayFlagRule(),
]
