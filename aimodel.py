def predict_risk(
    total_packets,
    ike_packets,
    esp_packets,
    ah_packets,
    udp_packets=0,
    tcp_packets=0
):

    # No packets

    if total_packets <= 0:

        return 20, "HIGH", 50


    ipsec_packets = (
        ike_packets +
        esp_packets +
        ah_packets
    )


    ipsec_percentage = (
        ipsec_packets /
        total_packets
    ) * 100


    # Base score

    score = 50


    # -------------------------
    # IKE analysis
    # -------------------------

    if ike_packets == 0:

        score -= 15

    elif ike_packets <= 5:

        score += 5

    elif ike_packets <= 20:

        score += 12

    else:

        score += 18


    # -------------------------
    # ESP analysis
    # -------------------------

    if esp_packets == 0:

        score -= 20

    elif esp_packets <= 10:

        score += 8

    elif esp_packets <= 50:

        score += 20

    else:

        score += 28


    # -------------------------
    # AH
    # -------------------------

    if ah_packets > 0:

        score += 3


    # -------------------------
    # IPsec percentage
    # -------------------------

    if ipsec_percentage >= 80:

        score += 8

    elif ipsec_percentage >= 50:

        score += 5

    elif ipsec_percentage < 10:

        score -= 10


    # Limit score

    score = max(
        0,
        min(score, 100)
    )


    # -------------------------
    # Risk
    # -------------------------

    if score >= 80:

        risk = "LOW"

    elif score >= 55:

        risk = "MEDIUM"

    else:

        risk = "HIGH"


    # -------------------------
    # Confidence
    # -------------------------

    confidence = 55


    if total_packets >= 20:

        confidence += 10


    if total_packets >= 100:

        confidence += 10


    if ipsec_packets > 0:

        confidence += 10


    if ike_packets > 0 and esp_packets > 0:

        confidence += 10


    confidence = min(
        confidence,
        95
    )


    return (
        score,
        risk,
        confidence
    )