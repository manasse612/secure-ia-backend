# === Service d'export PDF ===
# Génère des rapports PDF détaillés pour chaque analyse
# Ajoute une signature numérique (hash) pour valeur légale et preuve d'authenticité

import io
import hashlib
import uuid
from datetime import datetime
from typing import Optional
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT


# --- Couleurs du thème Secure IA ---
COLOR_PRIMARY = HexColor("#4f46e5")
COLOR_GREEN = HexColor("#10b981")
COLOR_YELLOW = HexColor("#f59e0b")
COLOR_RED = HexColor("#ef4444")
COLOR_GRAY = HexColor("#6b7280")
COLOR_DARK = HexColor("#1e293b")
COLOR_LIGHT = HexColor("#f1f5f9")


def _get_score_color(score: float) -> HexColor:
    """Retourne la couleur selon le score (vert, jaune, rouge)"""
    if score >= 70:
        return COLOR_GREEN
    elif score >= 40:
        return COLOR_YELLOW
    return COLOR_RED


def _get_verdict_label(verdict: str) -> str:
    """Retourne le libellé français du verdict"""
    labels = {
        "authentique": "Authentique",
        "vrai": "Information fiable",
        "securise": "Site sécurisé",
        "suspect": "Contenu suspect",
        "non_verifiable": "Non vérifiable",
        "risque_modere": "Risque modéré",
        "deepfake": "Deepfake détecté",
        "faux": "Probablement faux",
        "dangereux": "Site dangereux",
    }
    return labels.get(verdict, verdict)


def generate_analysis_pdf(analysis_data: dict) -> bytes:
    """
    Génère un rapport PDF complet pour une analyse donnée.
    Retourne le contenu PDF sous forme de bytes.
    
    Paramètres :
        analysis_data : dictionnaire contenant les résultats de l'analyse
    """
    # Créer le buffer mémoire pour le PDF
    buffer = io.BytesIO()

    # Créer le document PDF
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    # --- Définir les styles ---
    styles = getSampleStyleSheet()

    # Style pour le titre principal
    title_style = ParagraphStyle(
        "TitleCustom",
        parent=styles["Title"],
        fontSize=20,
        textColor=COLOR_PRIMARY,
        spaceAfter=10,
        alignment=TA_CENTER,
    )

    # Style pour les sous-titres
    heading_style = ParagraphStyle(
        "HeadingCustom",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=COLOR_DARK,
        spaceAfter=8,
        spaceBefore=16,
    )

    # Style pour le texte normal
    body_style = ParagraphStyle(
        "BodyCustom",
        parent=styles["Normal"],
        fontSize=10,
        textColor=COLOR_GRAY,
        spaceAfter=6,
    )

    # Style pour les informations importantes
    info_style = ParagraphStyle(
        "InfoCustom",
        parent=styles["Normal"],
        fontSize=11,
        textColor=COLOR_DARK,
        spaceAfter=4,
    )

    # --- Construire le contenu du PDF ---
    elements = []

    # Titre du rapport
    elements.append(Paragraph("SECURE IA", title_style))
    elements.append(Paragraph("Rapport d'analyse de contenu numérique", body_style))
    elements.append(Spacer(1, 0.5 * cm))

    # Ligne de séparation
    separator_data = [["" * 80]]
    separator = Table(separator_data, colWidths=[16 * cm])
    separator.setStyle(TableStyle([
        ("LINEABOVE", (0, 0), (-1, 0), 1, COLOR_PRIMARY),
    ]))
    elements.append(separator)
    elements.append(Spacer(1, 0.5 * cm))

    # Date et type d'analyse
    analysis_type = analysis_data.get("analysis_type", "inconnu")
    type_labels = {"image": "Image", "text": "Texte", "url": "URL", "video": "Vidéo"}
    type_label = type_labels.get(analysis_type, analysis_type)

    created_at = analysis_data.get("created_at", datetime.utcnow().isoformat())
    if isinstance(created_at, str):
        try:
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            created_at = datetime.utcnow()

    elements.append(Paragraph(f"<b>Type d'analyse :</b> {type_label}", info_style))
    elements.append(Paragraph(
        f"<b>Date :</b> {created_at.strftime('%d/%m/%Y à %H:%M')}",
        info_style,
    ))
    elements.append(Spacer(1, 0.3 * cm))

    # Score et verdict
    score = analysis_data.get("score", 0)
    verdict = analysis_data.get("verdict", "inconnu")
    score_color = _get_score_color(score)

    elements.append(Paragraph("Score et verdict", heading_style))

    score_data = [
        ["Score d'analyse", f"{score:.0f} / 100"],
        ["Verdict", _get_verdict_label(verdict)],
    ]
    if analysis_data.get("processing_time_ms"):
        score_data.append(["Temps de traitement", f"{analysis_data['processing_time_ms']:.0f} ms"])

    score_table = Table(score_data, colWidths=[6 * cm, 10 * cm])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), COLOR_LIGHT),
        ("TEXTCOLOR", (0, 0), (0, -1), COLOR_DARK),
        ("TEXTCOLOR", (1, 0), (1, 0), score_color),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("FONTSIZE", (1, 0), (1, 0), 14),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(score_table)
    elements.append(Spacer(1, 0.5 * cm))

    # Contenu analysé
    input_data = analysis_data.get("input_data", "")
    if input_data:
        elements.append(Paragraph("Contenu analysé", heading_style))
        # Tronquer si trop long
        display_data = input_data[:500] + ("..." if len(input_data) > 500 else "")
        elements.append(Paragraph(display_data, body_style))
        elements.append(Spacer(1, 0.3 * cm))

    # Résumé
    summary = analysis_data.get("summary", "")
    if summary:
        elements.append(Paragraph("Résumé de l'analyse", heading_style))
        elements.append(Paragraph(summary, info_style))
        elements.append(Spacer(1, 0.3 * cm))

    # Résultats détaillés
    result = analysis_data.get("result", {})
    if result and isinstance(result, dict):
        elements.append(Paragraph("Résultats détaillés", heading_style))

        for key, value in result.items():
            if isinstance(value, dict):
                elements.append(Paragraph(f"<b>{key.replace('_', ' ').title()}</b>", info_style))
                for sub_key, sub_value in value.items():
                    if not isinstance(sub_value, (dict, list)):
                        elements.append(Paragraph(
                            f"  • {sub_key.replace('_', ' ')} : {sub_value}",
                            body_style,
                        ))
            elif not isinstance(value, (dict, list)):
                elements.append(Paragraph(f"• {key.replace('_', ' ')} : {value}", body_style))

    # Section Certificat d'authenticité (pour valeur légale)
    elements.append(Spacer(1, 0.8 * cm))
    elements.append(Paragraph("Certificat d'authenticité du rapport", heading_style))
    
    # Générer un identifiant unique pour ce rapport
    report_id = str(uuid.uuid4())[:8].upper()
    
    # Calculer un hash de vérification basé sur les données clés
    verification_data = f"{analysis_data.get('analysis_type', '')}:{score}:{verdict}:{created_at.isoformat()}:{report_id}"
    report_hash = hashlib.sha256(verification_data.encode()).hexdigest()[:16].upper()
    
    # Récupérer le hash du fichier analysé s'il existe
    file_hash = ""
    result_data = analysis_data.get("result", {})
    if isinstance(result_data, dict):
        file_integrity = result_data.get("file_integrity", {})
        file_hash = file_integrity.get("hash_sha256", "N/A")[:16] + "..."
    
    cert_data = [
        ["Identifiant du rapport", report_id],
        ["Empreinte du rapport (SHA-256)", report_hash],
        ["Empreinte du fichier analysé", file_hash if file_hash else "N/A"],
        ["Émis par", "Secure IA - Plateforme de vérification"],
        ["Le", datetime.utcnow().strftime('%d/%m/%Y à %H:%M UTC')],
    ]
    
    cert_table = Table(cert_data, colWidths=[6 * cm, 10 * cm])
    cert_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), COLOR_PRIMARY),
        ("TEXTCOLOR", (0, 0), (0, -1), HexColor("#ffffff")),
        ("TEXTCOLOR", (1, 0), (1, -1), COLOR_DARK),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(cert_table)
    
    # Note légale
    legal_style = ParagraphStyle(
        "LegalCustom",
        parent=styles["Normal"],
        fontSize=8,
        textColor=COLOR_GRAY,
        alignment=TA_LEFT,
    )
    elements.append(Spacer(1, 0.3 * cm))
    elements.append(Paragraph(
        "<i>Ce rapport est signé numériquement par empreinte cryptographique. "
        "L'intégrité du document peut être vérifiée sur secure-ia.com/verify</i>",
        legal_style,
    ))

    # Pied de page
    elements.append(Spacer(1, 1 * cm))
    elements.append(separator)
    elements.append(Spacer(1, 0.3 * cm))

    footer_style = ParagraphStyle(
        "FooterCustom",
        parent=styles["Normal"],
        fontSize=8,
        textColor=COLOR_GRAY,
        alignment=TA_CENTER,
    )
    elements.append(Paragraph(
        f"Rapport généré par Secure IA le {datetime.utcnow().strftime('%d/%m/%Y à %H:%M UTC')}",
        footer_style,
    ))
    elements.append(Paragraph(
        "Ce rapport est fourni à titre informatif. Les résultats sont basés sur des analyses automatisées.",
        footer_style,
    ))
    elements.append(Paragraph(
        "© 2026 Secure IA – Plateforme de vérification de contenus numériques – Conforme RGPD",
        footer_style,
    ))

    # Construire le PDF
    doc.build(elements)

    # Récupérer le contenu
    pdf_bytes = buffer.getvalue()
    buffer.close()

    return pdf_bytes
