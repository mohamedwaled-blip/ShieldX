


def total_score(signals) -> int:
    return min(100, sum(s["points"] for s in signals))


def verdict_for(score: int) -> str:
    if score >= 70:
        return "خطير"
    if score >= 35:
        return "مشبوه"
    return "منخفض الخطورة"


def default_reason(score: int, signals) -> str:
    n = len(signals)
    if score >= 70:
        return f"اتكشف {n} مؤشر خطر، متفتحوش"
    if score >= 35:
        return f"فيه {n} مؤشر مشبوه، تعامل معاه بحذر"
    if n:
        return f"فيه {n} علامة بسيطة بس مفيش دليل قوي على خطورته"
    return "مفيش مؤشرات خطر واضحة، بس ده مش ضمان إنه آمن 100%"


def build_result(signals, reason=None, extra=None) -> dict:
    score = total_score(signals)
    result = {
        "verdict": verdict_for(score),
        "score": score,
        "reason": reason or default_reason(score, signals),
        "signals": signals,
    }
    if extra:
        result.update(extra)
    return result
