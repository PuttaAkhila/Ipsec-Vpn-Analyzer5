from scapy.all import rdpcap
from aimodel import predict_risk


def analyze_pcap(file_path):

    packets = rdpcap(file_path)

    total_packets = len(packets)


    # =============================
    # COUNTERS
    # =============================

    ike_packets = 0
    esp_packets = 0
    ah_packets = 0

    udp_packets = 0
    tcp_packets = 0

    ike_v1_packets = 0
    ike_v2_packets = 0

    nat_t_packets = 0


    # =============================
    # PACKET ANALYSIS
    # =============================

    for packet in packets:

        # -------------------------
        # UDP
        # -------------------------

        if packet.haslayer("UDP"):

            udp_packets += 1

            sport = packet["UDP"].sport
            dport = packet["UDP"].dport


            # IKE ports

            if (
                sport in [500, 4500]
                or
                dport in [500, 4500]
            ):

                ike_packets += 1


                # NAT-T

                if (
                    sport == 4500
                    or
                    dport == 4500
                ):

                    nat_t_packets += 1


                # -------------------------
                # IKE VERSION
                # -------------------------

                if packet.haslayer("Raw"):

                    try:

                        data = bytes(
                            packet["Raw"].load
                        )


                        if len(data) >= 18:

                            version = data[17]

                            major_version = (
                                version >> 4
                            )


                            if major_version == 1:

                                ike_v1_packets += 1


                            elif major_version == 2:

                                ike_v2_packets += 1

                    except Exception:

                        pass


        # -------------------------
        # TCP
        # -------------------------

        if packet.haslayer("TCP"):

            tcp_packets += 1


        # -------------------------
        # ESP
        # -------------------------

        if packet.haslayer("ESP"):

            esp_packets += 1

        elif packet.haslayer("IP"):

            if packet["IP"].proto == 50:

                esp_packets += 1


        # -------------------------
        # AH
        # -------------------------

        if packet.haslayer("AH"):

            ah_packets += 1

        elif packet.haslayer("IP"):

            if packet["IP"].proto == 51:

                ah_packets += 1


    # =============================
    # AI RISK ANALYSIS
    # =============================

    score, risk, confidence = predict_risk(

        total_packets,

        ike_packets,

        esp_packets,

        ah_packets,

        udp_packets,

        tcp_packets
    )


    # =============================
    # IKE VERSION
    # =============================

    if ike_v2_packets > 0:

        ike_version = "IKEv2"

    elif ike_v1_packets > 0:

        ike_version = "IKEv1"

    elif ike_packets > 0:

        ike_version = "IKE detected"

    else:

        ike_version = "Not detected"


    # =============================
    # VPN MODE
    # =============================

    if esp_packets > 0:

        vpn_mode = "Tunnel / ESP traffic"

    elif ah_packets > 0:

        vpn_mode = "AH / IPsec"

    elif ike_packets > 0:

        vpn_mode = "IKE negotiation"

    else:

        vpn_mode = "Not detected"


    # =============================
    # ENCRYPTION
    # =============================

    if esp_packets > 0:

        encryption = (
            "ESP encrypted traffic detected"
        )

    elif ike_packets > 0:

        encryption = (
            "Not detected"
        )

    else:

        encryption = "Not detected"


    # =============================
    # AUTHENTICATION
    # =============================

    if ike_packets > 0:

        authentication = (
            "IKE authentication detected"
        )

    else:

        authentication = "Not detected"


    # =============================
    # DH GROUP
    # =============================

    # Scapy basic packet detection
    # cannot reliably identify actual
    # DH proposal without deeper IKE parsing.

    dh_group = "Not detected"


    # =============================
    # PFS
    # =============================

    pfs = "Not detected"


    # =============================
    # REPLAY PROTECTION
    # =============================

    if esp_packets > 0:

        replay_protection = (
            "ESP sequence/replay mechanism present"
        )

    else:

        replay_protection = "Not detected"


    # =============================
    # TERMINAL OUTPUT
    # =============================

    print()
    print("======================================")
    print("       IPsec VPN ANALYSIS")
    print("======================================")

    print(
        "Total packets :", total_packets
    )

    print(
        "IKE packets   :", ike_packets
    )

    print(
        "IKEv1 packets :", ike_v1_packets
    )

    print(
        "IKEv2 packets :", ike_v2_packets
    )

    print(
        "NAT-T packets :", nat_t_packets
    )

    print(
        "ESP packets   :", esp_packets
    )

    print(
        "AH packets    :", ah_packets
    )

    print("--------------------------------------")

    print(
        "Security Score:", score
    )

    print(
        "Risk Level    :", risk
    )

    print(
        "AI Confidence :", confidence
    )

    print("--------------------------------------")

    print(
        "IKE Version   :", ike_version
    )

    print(
        "VPN Mode      :", vpn_mode
    )

    print(
        "Encryption    :", encryption
    )

    print(
        "Authentication:", authentication
    )

    print(
        "DH Group      :", dh_group
    )

    print(
        "PFS           :", pfs
    )

    print(
        "Replay        :", replay_protection
    )

    print("======================================")
    print()


    # =============================
    # RETURN JSON
    # =============================

    return {

        "total_packets":
            total_packets,

        "ike_packets":
            ike_packets,

        "esp_packets":
            esp_packets,

        "ah_packets":
            ah_packets,

        "udp_packets":
            udp_packets,

        "tcp_packets":
            tcp_packets,

        "security_score":
            score,

        "risk_level":
            risk,

        "ai_confidence":
            confidence,

        "ike_version":
            ike_version,

        "vpn_mode":
            vpn_mode,

        "encryption":
            encryption,

        "authentication":
            authentication,

        "dh_group":
            dh_group,

        "pfs":
            pfs,

        "replay_protection":
            replay_protection
    }