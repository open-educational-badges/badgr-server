import base64
import math
import os
from functools import partial
from io import BytesIO
from json import loads as json_loads
import cairosvg


import qrcode
from badgeuser.models import BadgeUser
from django.conf import settings
from django.db.models import Max
from issuer.models import BadgeInstance, LearningPath
from mainsite.utils import get_name
from django.core.files.storage import DefaultStorage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    Image,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepInFrame,
)

font_path_rubik_regular = os.path.join(
    os.path.dirname(__file__), "static", "fonts", "Rubik-Regular.ttf"
)
font_path_rubik_medium = os.path.join(
    os.path.dirname(__file__), "static", "fonts", "Rubik-Medium.ttf"
)
font_path_rubik_bold = os.path.join(
    os.path.dirname(__file__), "static", "fonts", "Rubik-Bold.ttf"
)
font_path_rubik_italic = os.path.join(
    os.path.dirname(__file__), "static", "fonts", "Rubik-Italic.ttf"
)

pdfmetrics.registerFont(TTFont("Rubik-Regular", font_path_rubik_regular))
pdfmetrics.registerFont(TTFont("Rubik-Medium", font_path_rubik_medium))
pdfmetrics.registerFont(TTFont("Rubik-Bold", font_path_rubik_bold))
pdfmetrics.registerFont(TTFont("Rubik-Italic", font_path_rubik_italic))


class BadgePDFCreator:
    def __init__(self):
        self.competencies = []
        self.used_space = 0

    def add_badge_image(self, first_page_content, badgeImage):
        image_width = 180
        img = image_file_to_image(badgeImage, image_width=image_width)
        first_page_content.append(img)
        self.used_space += img.imageHeight if img is not None else 0

    def add_recipient_name(
        self,
        first_page_content,
        name,
        issuedOn,
        activityStartDate=None,
        activityEndDate=None,
        activityCity=None,
        activityOnline=False,
    ):
        first_page_content.append(Spacer(1, 58))
        self.used_space += 58
        recipient_style = ParagraphStyle(
            name="Recipient",
            fontSize=18,
            leading=21.6,
            textColor="#492E98",
            fontName="Rubik-Bold",
            alignment=TA_CENTER,
        )

        recipient_name = f"<strong>{name}</strong>"
        first_page_content.append(Paragraph(recipient_name, recipient_style))
        first_page_content.append(Spacer(1, 25))
        self.used_space += 46.6  # spacer and paragraph

        text_style = ParagraphStyle(name="Text_Style", fontSize=18, alignment=TA_CENTER)

        if (
            activityStartDate
            and activityEndDate
            and activityStartDate != activityEndDate
        ):
            if activityStartDate.year == activityEndDate.year:
                date_text = (
                    f"<strong>{activityStartDate.strftime('%d.%m.')}"
                    f" – {activityEndDate.strftime('%d.%m.%Y')}</strong>"
                )
            else:
                date_text = (
                    f"<strong>{activityStartDate.strftime('%d.%m.%Y')}"
                    f" – {activityEndDate.strftime('%d.%m.%Y')}</strong>"
                )
            text = "hat vom " + date_text
        elif activityStartDate:
            date_text = f"<strong>{activityStartDate.strftime('%d.%m.%Y')}</strong>"
            text = "hat am " + date_text
        else:
            date_text = f"<strong>{issuedOn.strftime('%d.%m.%Y')}</strong>"
            text = "hat am " + date_text

        if activityCity:
            text += f" <strong>in {activityCity}</strong>"
        elif activityOnline:
            text += " <strong>online</strong>"

        first_page_content.append(Paragraph(text, text_style))

        first_page_content.append(Spacer(1, 10))
        self.used_space += 28  # spacer and paragraph

        text = "den folgenden Badge erworben:"
        first_page_content.append(Paragraph(text, text_style))
        first_page_content.append(Spacer(1, 25))
        self.used_space += 43  # spacer and paragraph

    def add_title(self, first_page_content, badge_class_name):
        document_width, _ = A4
        line_height = 30
        title_style = ParagraphStyle(
            name="Title",
            fontSize=20,
            textColor="#492E98",
            fontName="Rubik-Bold",
            leading=line_height,
            alignment=TA_CENTER,
        )
        first_page_content.append(Spacer(1, 10))

        title = badge_class_name
        width = document_width - 40
        max_h = line_height * 2
        p = Paragraph(f"<strong>{title}</strong>", title_style)
        p.wrap(width, max_h)
        if len(p.blPara.lines) <= 2:
            first_page_content.append(KeepInFrame(width, max_h, [p]))
        else:
            ellipsis = "\u2026"
            words = title.split()
            while words:
                trial = " ".join(words) + ellipsis
                p = Paragraph(f"<strong>{trial}</strong>", title_style)
                p.wrap(width, max_h)
                if len(p.blPara.lines) <= 2:
                    first_page_content.append(KeepInFrame(width, max_h, [p]))
                    break
                words.pop()
        first_page_content.append(Spacer(1, 15))
        self.used_space += (
            len(p.blPara.lines) * line_height + 25
        )  # badge class name and spaces

    def truncate_text(text, max_words=70):
        words = text.split()
        if len(words) > max_words:
            return " ".join(words[:max_words]) + "..."
        else:
            return text

    def add_dynamic_spacer(self, first_page_content, text):
        line_char_count = 79
        line_height = 16.5
        num_lines = math.ceil(len(text) / line_char_count)
        spacer_height = 160 - (num_lines - 1) * line_height
        spacer_height = max(spacer_height, 0)
        first_page_content.append(Spacer(1, spacer_height))
        self.used_space += spacer_height

    def add_description(self, first_page_content, description):
        description_style = ParagraphStyle(
            name="Description",
            fontSize=12,
            fontName="Rubik-Regular",
            leading=16.5,
            alignment=TA_CENTER,
            leftIndent=20,
            rightIndent=20,
        )
        first_page_content.append(Paragraph(description, description_style))
        line_char_count = 79
        line_height = 16.5
        num_lines = math.ceil(len(description) / line_char_count)
        self.used_space += num_lines * line_height

    def add_issued_by(self, first_page_content, issued_by, qrCodeImage=None):
        issued_by_style = ParagraphStyle(
            name="IssuedBy",
            fontSize=10,
            textColor="#323232",
            fontName="Rubik-Medium",
            alignment=TA_CENTER,
            backColor="#F5F5F5",
            leftIndent=-45,
            rightIndent=-45,
        )
        # use document width to calculate the table and its size
        document_width, _ = A4

        qr_code_height = 0
        if qrCodeImage:
            if qrCodeImage.startswith("data:image"):
                qrCodeImage = qrCodeImage.split(",")[1]  # Entfernt das Präfix

            image = base64.b64decode(qrCodeImage)
            qrCodeImage = BytesIO(image)
            qrCodeImage = ImageReader(qrCodeImage)

            rounded_img = RoundedImage(
                img_path=qrCodeImage,
                width=57,
                height=57,
                border_color="#492E98",
                border_width=1,
                padding=1,
                radius=2 * mm,
            )

            img_table = Table([[rounded_img]], colWidths=[document_width])
            img_table.hAlign = "CENTER"
            img_table.setStyle(
                TableStyle(
                    [
                        ("ALIGN", (0, 0), (0, 0), "CENTER"),
                        ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F5F5F5")),
                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            -45,
                        ),  # Negative padding to extend beyond the document margin
                        ("RIGHTPADDING", (0, 0), (-1, -1), -45),
                        ("TOPPADDING", (0, 0), (-1, -1), 20),
                    ]
                )
            )
            first_page_content.append(img_table)
            qr_code_height = 57 + 20

        # Add the simple html
        content_html = """
            <br/><span fontName="Rubik-Bold">ERSTELLT ÜBER <a href="https://openbadges.education"
            color="#1400FF"
            underline="true">OPENBADGES.EDUCATION</a></span>
            <br/>
            <span fontName="Rubik-Regular">Der digitale Badge kann über den QR-Code abgerufen werden</span>
            <br/><br/>
        """

        # Add content as a Paragraph to first_page_content
        first_page_content.append(Paragraph(content_html, issued_by_style))

        paragraph_height = 60
        self.used_space += qr_code_height + paragraph_height

    # draw header with image of institution and a hr
    def header(self, canvas, doc, content, instituteName):
        canvas.saveState()
        header_height = 0

        if content is not None:
            # for non-square images move them into the center of the 80x80 reserved space
            # by going up 40 and then down half the height of the image.
            # If the image is 80 the offset will be 0 and thus the picture is placed at 740
            content.drawOn(canvas, doc.leftMargin, 740 + (40 - content.drawHeight / 2))
            header_height += content.drawHeight

        canvas.setStrokeColor("#492E98")
        canvas.setLineWidth(1)
        canvas.line(doc.leftMargin + 100, 775, doc.leftMargin + doc.width, 775)
        header_height += 1
        # name of institute barely above the hr that was just set
        canvas.setFont("Rubik-Medium", 12)
        max_length = 50
        line_height = 12
        # logic if a linebreak is needed
        if len(instituteName) > max_length:
            split_index = instituteName.rfind(" ", 0, max_length)
            if split_index == -1:
                split_index = max_length

            line1 = instituteName[:split_index]
            line2 = instituteName[split_index:].strip()

            canvas.drawString(doc.leftMargin + 100, 778 + line_height, line1)
            canvas.drawString(doc.leftMargin + 100, 778, line2)
            header_height += 2 * line_height
        else:
            canvas.drawString(doc.leftMargin + 100, 778, instituteName)
            header_height += line_height

        self.used_space += header_height
        canvas.restoreState()

    def add_competencies(self, Story, competencies, name, badge_name):
        num_competencies = len(competencies)
        page_used_space = 0

        if num_competencies > 0:
            max_studyload = str(max(c["studyLoad"] for c in competencies))
            competenciesPerPage = 9

            Story.append(PageBreak())
            Story.append(Spacer(1, 70))
            page_used_space += 70

            title_style = ParagraphStyle(
                name="Title",
                fontSize=20,
                fontName="Rubik-Medium",
                textColor="#492E98",
                alignment=TA_LEFT,
                textTransform="uppercase",
            )
            text_style = ParagraphStyle(
                name="Text",
                fontSize=18,
                leading=20,
                textColor="#323232",
                alignment=TA_LEFT,
            )

            Story.append(Paragraph("Kompetenzen", title_style))
            Story.append(Spacer(1, 15))
            page_used_space += 35  # Title height + spacing

            text = f"die <strong>{name}</strong> mit dem Badge <strong>{badge_name}</strong> erworben hat:"
            Story.append(Paragraph(text, text_style))
            Story.append(Spacer(1, 10))
            page_used_space += 30  # Text height + spacer

            for i in range(num_competencies):
                if i != 0 and i % competenciesPerPage == 0:
                    Story.append(PageBreak())
                    page_used_space = 0

                    Story.append(Spacer(1, 70))
                    page_used_space += 70

                    Story.append(Paragraph("<strong>Kompetenzen</strong>", title_style))
                    Story.append(Spacer(1, 15))
                    page_used_space += 35  # Title height + spacer

                    text = f"die <strong>{name}</strong> mit dem Badge <strong>{badge_name}</strong> erworben hat:"
                    Story.append(Paragraph(text, text_style))
                    Story.append(Spacer(1, 20))
                    page_used_space += 40  # Text height + spacer

                studyload = "%s:%s h" % (
                    math.floor(competencies[i]["studyLoad"] / 60),
                    str(competencies[i]["studyLoad"] % 60).zfill(2),
                )
                competency_name = competencies[i]["name"]
                competency = competency_name
                if competencies[i] not in self.competencies:
                    self.competencies.append(competencies[i])
                rounded_rect = RoundedRectFlowable(
                    0,
                    -10,
                    515,
                    45,
                    10,
                    text=competency,
                    strokecolor="#492E98",
                    fillcolor="#F5F5F5",
                    studyload=studyload,
                    max_studyload=max_studyload,
                    esco=competencies[i]["framework_identifier"],
                )
                Story.append(rounded_rect)
                Story.append(Spacer(1, 10))
                page_used_space += 55  # RoundedRectFlowable height 45 + spacing

            self.used_space += page_used_space

    def add_learningpath_badges(self, Story, badges, name, badge_name, competencies):
        num_badges = len(badges)
        if num_badges > 0:
            badgesPerPage = 5

            Story.append(PageBreak())
            Story.append(Spacer(1, 70))

            title_style = ParagraphStyle(
                name="Title",
                fontSize=20,
                fontName="Rubik-Medium",
                textColor="#492E98",
                alignment=TA_LEFT,
                textTransform="uppercase",
            )
            text_style = ParagraphStyle(
                name="Text",
                fontSize=18,
                leading=20,
                textColor="#323232",
                alignment=TA_LEFT,
            )

            Story.append(Paragraph("Badges", title_style))

            Story.append(Spacer(1, 15))

            text = f"die <strong>{name}</strong> mit dem Micro Degree <strong>{badge_name}</strong> erworben hat:"
            Story.append(Paragraph(text, text_style))
            Story.append(Spacer(1, 30))

            for i in range(num_badges):
                extensions = badges[i].badgeclass.cached_extensions()
                categoryExtension = extensions.get(name="extensions:CategoryExtension")
                category = json_loads(categoryExtension.original_json)["Category"]
                if category == "competency":
                    competencies = badges[i].badgeclass.json[
                        "extensions:CompetencyExtension"
                    ]
                    for competency in competencies:
                        if competency not in self.competencies:
                            self.competencies.append(competency)

                if i != 0 and i % badgesPerPage == 0:
                    Story.append(PageBreak())
                    Story.append(Spacer(1, 70))
                    Story.append(Paragraph("<strong>Badges</strong>", title_style))
                    Story.append(Spacer(1, 15))

                    text = (
                        f"die <strong>{name}</strong> mit dem Micro Degree"
                        f"<strong>{badge_name}</strong> erworben hat:"
                    )

                    Story.append(Paragraph(text, text_style))
                    Story.append(Spacer(1, 30))

                img = image_file_to_image(badges[i].image, 74)

                lp_badge_info_style = ParagraphStyle(
                    name="Text",
                    fontSize=14,
                    leading=16.8,
                    textColor="#323232",
                    alignment=TA_LEFT,
                )

                badge_title = Paragraph(
                    f"<strong>{badges[i].badgeclass.name}</strong>", lp_badge_info_style
                )
                issuer = Paragraph(
                    badges[i].badgeclass.issuer.name, lp_badge_info_style
                )
                date = Paragraph(
                    badges[i].issued_on.strftime("%d.%m.%Y"), lp_badge_info_style
                )
                data = [[img, [badge_title, Spacer(1, 10), issuer, Spacer(1, 5), date]]]

                table = Table(data, colWidths=[100, 450])

                table.setStyle(
                    TableStyle(
                        [
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("ALIGN", (0, 0), (0, 0), "CENTER"),
                            ("LEFTPADDING", (1, 0), (1, 0), 12),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 20),
                        ]
                    )
                )

                Story.append(table)
                Story.append(Spacer(1, 10))

            self.add_competencies(Story, self.competencies, name, badge_name)

    def generate_qr_code(self, badge_instance, origin):
        # build the qr code in the backend

        qrCodeImageUrl = f"{origin}/public/assertions/{badge_instance.entity_id}"
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qrCodeImageUrl)
        qr.make(fit=True)
        qrCodeImage = qr.make_image(fill_color="black", back_color="white")

        buffered = BytesIO()
        qrCodeImage.save(buffered, format="PNG")
        qrCodeImageBase64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
        return qrCodeImageBase64

    def add_criteria(self, Story, criteria):
        if not criteria:
            return

        title_style = ParagraphStyle(
            name="Title",
            fontSize=20,
            fontName="Rubik-Medium",
            textColor="#492E98",
            alignment=TA_LEFT,
            textTransform="uppercase",
        )

        Story.append(Spacer(1, 30))
        self.used_space += 30

        Story.append(Paragraph("Vergabe-Kriterien", title_style))
        Story.append(Spacer(1, 15))
        self.used_space += 35

        name_style = ParagraphStyle(
            name="Name", fontSize=16, leading=18, textColor="#323232", alignment=TA_LEFT
        )

        description_style = ParagraphStyle(
            name="Description",
            fontSize=14,
            leading=16,
            textColor="#777777",
            alignment=TA_LEFT,
            fontName="Rubik-Italic",
        )

        for index, item in enumerate(criteria):
            criteria_space = 15 + 18  # criteria name line height + spacing

            # Check if adding criteria would exceed the page
            if self.used_space + criteria_space > 680:
                Story.append(PageBreak())
                Story.append(Spacer(1, 70))

                Story.append(Paragraph("Vergabe-Kriterien", title_style))
                Story.append(Spacer(1, 15))

                # Reset used space counter with the header space
                self.used_space = 70 + 35  # Header spacer + title and spacing

            if "name" in item and item["name"]:
                bullet_text = f"• {item['name']}"
                Story.append(Spacer(1, 15))
                Story.append(Paragraph(bullet_text, name_style))
                self.used_space += criteria_space

            if "description" in item and item["description"]:
                line_char_count = 79
                line_height = 16.5
                num_lines = math.ceil(len(item["description"]) / line_char_count)
                criteria_space += num_lines * line_height
                if self.used_space + criteria_space > 750:
                    Story.append(PageBreak())
                    Story.append(Spacer(1, 70))
                    Story.append(Paragraph("Vergabe-Kriterien", title_style))
                    Story.append(Spacer(1, 15))
                    self.used_space = 70 + 35  # Header spacer + title and spacing
                    Story.append(Paragraph(item["description"], description_style))
                    self.used_space += criteria_space

                else:
                    self.used_space += num_lines * line_height
                    Story.append(Spacer(1, 5))
                    Story.append(Paragraph(item["description"], description_style))

        Story.append(Spacer(1, 15))
        self.used_space += 15

    def add_evidence(self, Story, evidence_items, narrative, category):
        """
        Adds the evidence section to the Story

        evidence_items: list of dicts from JSONField
        narrative: string (same for all list items)
        category: badge category
        """

        if not evidence_items and not narrative:
            return

        title_style = ParagraphStyle(
            name="EvidenceTitle",
            fontSize=20,
            fontName="Rubik-Medium",
            textColor="#492E98",
            alignment=TA_LEFT,
            textTransform="uppercase",
        )

        narrative_style = ParagraphStyle(
            name="Narrative",
            fontSize=16,
            leading=18,
            textColor="#323232",
            alignment=TA_LEFT,
        )

        linknote_style = ParagraphStyle(
            name="LinkNote",
            fontSize=12,
            leading=17,
            textColor="#323232",
            alignment=TA_LEFT,
        )

        space_needed = 0
        title_height = 20 + 15  # font size + spacer
        space_needed += title_height

        has_evidence_url = any(item.evidence_url for item in (evidence_items or []))
        if has_evidence_url:
            space_needed += 10 + 16 + 10  # spacer + icon + spacer

        narratives = [
            item.narrative for item in (evidence_items or []) if item.narrative
        ]
        if narrative or narratives:
            narrative_text = narratives[0] if narratives else narrative
            line_char_count = 79
            line_height = 18
            num_lines = math.ceil(len(narrative_text) / line_char_count)
            narrative_height = num_lines * line_height + 15
            space_needed += narrative_height

        # some top spacing before section
        space_needed += 30

        if self.used_space + space_needed > 680 or category == "participation":
            Story.append(PageBreak())
            Story.append(Spacer(1, 70))
            self.used_space = 70  # reset used space with header
        else:
            self.used_space += 30  # top spacer

        Story.append(Paragraph("Narrativ", title_style))
        Story.append(Spacer(1, 15))
        self.used_space += 35  # title + spacer

        if has_evidence_url:
            Story.append(Spacer(1, 10))
            icon_path = os.path.join(settings.STATIC_URL, "images/external_link.png")
            icon_img = Image(icon_path, width=16, height=16)

            t = Table(
                [
                    [
                        icon_img,
                        Paragraph(
                            "Auf der Badge-Detail-Seite ist ein Link zum Nachweis hinterlegt (s. QR-Code, Seite 1).",
                            linknote_style,
                        ),
                    ]
                ],
                colWidths=[20, 475],
            )
            t.setStyle(
                TableStyle(
                    [
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 0),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            Story.append(t)
            Story.append(Spacer(1, 10))
            self.used_space += 40

        if narrative or narratives:
            narrative_text = narratives[0] if narratives else narrative
            Story.append(Paragraph(narrative_text, narrative_style))
            Story.append(Spacer(1, 15))
            self.used_space += narrative_height

    def generate_pdf(self, badge_instance, badge_class, origin):
        buffer = BytesIO()
        competencies = badge_class.json["extensions:CompetencyExtension"]
        criteria = badge_class.criteria
        try:
            name = get_name(badge_instance)
        except BadgeUser.DoesNotExist:
            # To resolve the issue with old awarded badges that doesn't
            # include recipient-name and only have recipient-email
            # We use email as this is the only identifier we have
            name = badge_instance.recipient_identifier
            # raise Http404

        self.used_space = 0

        first_page_content = []

        self.add_recipient_name(
            first_page_content,
            name,
            badge_instance.issued_on,
            activityStartDate=badge_instance.activity_start_date,
            activityEndDate=badge_instance.activity_end_date,
            activityCity=badge_instance.activity_city,
            activityOnline=badge_instance.activity_online,
        )
        self.add_badge_image(first_page_content, badge_instance.image)
        self.add_title(first_page_content, badge_class.name)
        self.add_description(first_page_content, badge_class.description)
        self.add_dynamic_spacer(first_page_content, (badge_class.description or ""))
        self.add_issued_by(
            first_page_content,
            badge_class.issuer.name,
            self.generate_qr_code(badge_instance, origin),
        )

        # doc template with margins according to design doc
        doc = BaseDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=40,
            rightMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="Justify", alignment=TA_JUSTIFY))

        Story = []
        Story.extend(first_page_content)

        extensions = badge_class.cached_extensions()
        categoryExtension = extensions.get(name="extensions:CategoryExtension")
        category = json_loads(categoryExtension.original_json)["Category"]

        if category == "learningpath":
            lp = LearningPath.objects.filter(participationBadge=badge_class).first()
            lp_badges = [badge.badge for badge in lp.learningpath_badges]
            badgeuser = BadgeUser.objects.get(email=badge_instance.recipient_identifier)
            badge_ids = (
                BadgeInstance.objects.filter(
                    badgeclass__in=lp_badges,
                    recipient_identifier__in=badgeuser.verified_emails,
                )
                .values("badgeclass")
                .annotate(max_id=Max("id"))
                .values_list("max_id", flat=True)
            )

            badgeinstances = BadgeInstance.objects.filter(id__in=badge_ids)
            self.add_learningpath_badges(
                Story, badgeinstances, name, badge_class.name, competencies=competencies
            )
        else:
            self.used_space = 0  # Reset used_space for competencies page
            self.add_competencies(Story, competencies, name, badge_class.name)
            self.add_criteria(Story, criteria)
            self.add_evidence(
                Story,
                evidence_items=badge_instance.evidence_items,
                narrative=badge_instance.narrative,
                category=category,
            )

        frame = Frame(
            doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal"
        )

        try:
            imageContent = image_file_to_image(badge_instance.issuer.image)
        except Exception:
            imageContent = None
        template = PageTemplate(
            id="header",
            frames=frame,
            onPage=partial(
                self.header,
                content=imageContent,
                instituteName=badge_instance.issuer.name,
            ),
        )
        doc.addPageTemplates([template])
        doc.build(Story, canvasmaker=partial(PageNumCanvas, self.competencies))
        pdfContent = buffer.getvalue()
        buffer.close()
        return pdfContent


# Class for rounded image as reportlabs table cell don't support rounded corners
# taken from AI
class RoundedImage(Flowable):
    def __init__(
        self, img_path, width, height, border_color, border_width, padding, radius
    ):
        super().__init__()
        self.img_path = img_path
        self.width = width
        self.height = height
        self.border_color = border_color
        self.border_width = border_width
        self.padding = padding
        self.radius = radius

    def draw(self):
        # Calculate total padding to prevent image overlap
        total_padding = self.padding + self.border_width + 1.8

        # Draw the rounded rectangle for the border
        canvas = self.canv
        canvas.setFillColor("white")
        canvas.setStrokeColor(self.border_color)
        canvas.setLineWidth(self.border_width)
        canvas.roundRect(
            0,  # Start at the lower-left corner of the Flowable
            0,
            self.width + 2 * total_padding,  # Width includes padding on both sides
            self.height + 2 * total_padding,  # Height includes padding on both sides
            self.radius,  # Radius for rounded corners,
            stroke=1,
            fill=1,
        )

        # Draw the image inside the rounded rectangle
        canvas.drawImage(
            self.img_path,
            total_padding,  # Offset by total padding to stay within rounded border
            total_padding,
            width=self.width,
            height=self.height,
            mask="auto",
        )


class RoundedRectFlowable(Flowable):
    def __init__(
        self,
        x,
        y,
        width,
        height,
        radius,
        text,
        strokecolor,
        fillcolor,
        studyload,
        max_studyload,
        esco="",
    ):
        super().__init__()
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.radius = radius
        self.strokecolor = strokecolor
        self.fillcolor = fillcolor
        self.text = text
        self.studyload = studyload
        self.max_studyload = max_studyload
        self.esco = esco

    def split_text(self, text, max_width):
        words = text.split()
        lines = []
        current_line = ""

        for word in words:
            test_line = f"{current_line} {word}".strip()
            if self.canv.stringWidth(test_line, "Rubik-Medium", 12) <= max_width:
                current_line = test_line
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word

        lines.append(current_line)
        return lines

    def draw(self):
        self.canv.setFillColor(self.fillcolor)
        self.canv.setStrokeColor(self.strokecolor)
        self.canv.roundRect(
            self.x, self.y, self.width, self.height, self.radius, stroke=1, fill=1
        )

        self.canv.setFillColor("#323232")
        text_width = self.canv.stringWidth(self.text)
        self.canv.setFont("Rubik-Medium", 12)
        if text_width > self.width - 175:
            available_text_width = self.width - 150
            y_text_position = self.y + 25
        else:
            available_text_width = self.width - 150
            y_text_position = self.y + 17.5

        text_lines = self.split_text(self.text, available_text_width)

        for line in text_lines:
            self.canv.drawString(self.x + 10, y_text_position, line)
            y_text_position -= 15

        self.canv.setFillColor("blue")
        if self.esco:
            last_line_width = self.canv.stringWidth(text_lines[-1])
            self.canv.setFillColor("blue")
            self.canv.drawString(
                self.x + 10 + last_line_width, y_text_position + 15, " [E]"
            )
            self.canv.linkURL(
                self.esco,
                (self.x, self.y, self.width, self.height),
                relative=1,
                thickness=0,
            )

        self.canv.setFillColor("#492E98")
        self.canv.setFont("Rubik-Regular", 14)
        studyload_width = self.canv.stringWidth(self.studyload)
        self.canv.drawString(
            self.x + 500 - (studyload_width + 10), self.y + 15, self.studyload
        )

        max_studyload_width = self.canv.stringWidth(self.max_studyload)
        clockIcon = ImageReader("{}images/clock-icon.png".format(settings.STATIC_URL))
        self.canv.drawImage(
            clockIcon,
            self.x + 475 - (max_studyload_width + 35),
            self.y + 12.5,
            width=15,
            height=15,
            mask="auto",
            preserveAspectRatio=True,
        )


# Inspired by https://www.blog.pythonlibrary.org/2013/08/12/reportlab-how-to-add-page-numbers/
class PageNumCanvas(canvas.Canvas):
    """
    http://code.activestate.com/recipes/546511-page-x-of-y-with-reportlab/
    http://code.activestate.com/recipes/576832/
    """

    # ----------------------------------------------------------------------
    def __init__(self, competencies, *args, **kwargs):
        """Constructor"""
        canvas.Canvas.__init__(self, *args, **kwargs)
        self.pages = []
        self.competencies = competencies

    # ----------------------------------------------------------------------
    def showPage(self):
        """
        On a page break, add information to the list
        """
        self.pages.append(dict(self.__dict__))
        self._startPage()

    # ----------------------------------------------------------------------
    def save(self):
        """
        Add the page number to each page (page x of y)
        """
        page_count = len(self.pages)

        for page in self.pages:
            self.__dict__.update(page)
            self.draw_page_number(page_count)
            canvas.Canvas.showPage(self)

        canvas.Canvas.save(self)

    # ----------------------------------------------------------------------
    def draw_page_number(self, page_count):
        """
        Add the page number
        """
        page = "%s / %s" % (self._pageNumber, page_count)
        self.setStrokeColor("#492E98")
        page_width = self._pagesize[0]
        self.line(10, 17.5, page_width / 2 - 20, 17.5)
        self.line(page_width / 2 + 20, 17.5, page_width - 10, 17.5)
        self.setFont("Rubik-Regular", 10)
        self.drawCentredString(page_width / 2, 15, page)
        if self._pageNumber == page_count:
            self.setLineWidth(3)
            self.line(10, 10, page_width - 10, 10)
            num_competencies = len(self.competencies)
            if num_competencies > 0:
                esco = any(c["framework"] for c in self.competencies)
                if esco:
                    self.draw_esco_info(page_width)

    # Draws ESCO competency information
    def draw_esco_info(self, page_width):
        self.setStrokeColor("#777777")
        self.setLineWidth(1)
        self.line(10, 75, page_width, 75)
        text_style = ParagraphStyle(
            name="Text_Style",
            fontName="Rubik-Italic",
            fontSize=10,
            leading=13,
            alignment=TA_CENTER,
            leftIndent=-35,
            rightIndent=-35,
        )
        link_text = (
            "<span><i>(E) = Kompetenz nach ESCO (European Skills, Competences, Qualifications and Occupations). <br/>"
            'Die Kompetenzbeschreibungen gemäß ESCO sind abrufbar über "'
            '<a color="blue" href="https://esco.ec.europa.eu/de">https://esco.ec.europa.eu/de</a>.</i></span>'
        )
        paragraph_with_link = Paragraph(link_text, text_style)
        story = [paragraph_with_link]
        story[0].wrapOn(self, page_width - 20, 50)
        story[0].drawOn(self, 10, 40)


def image_file_to_image(image, image_width=80):
    file_ext = image.path.split(".")[-1].lower()
    imageContent = None
    if file_ext == "svg":
        storage = DefaultStorage()
        bio = BytesIO()
        file_path = image.name
        try:
            with storage.open(file_path, "rb") as svg_file:
                cairosvg.svg2png(file_obj=svg_file, write_to=bio, dpi=300, scale=4)
        except IOError:
            raise ValueError(f"Failed to convert SVG to PNG: {image}")

        bio.seek(0)
        dummy = Image(bio)
        aspect = dummy.imageHeight / dummy.imageWidth
        imageContent = Image(bio, width=image_width, height=image_width * aspect)
    elif file_ext in ["png", "jpg", "jpeg", "gif"]:
        dummy = Image(image)
        aspect = dummy.imageHeight / dummy.imageWidth
        try:
            image.open()
            img_data = BytesIO(image.read())
            image.close()
            imageContent = Image(
                img_data, width=image_width, height=image_width * aspect
            )
        except Exception as e:
            print(f"Unexpected error for image {image}: {e}")
    else:
        raise ValueError(f"Unsupported file type: {file_ext}")

    return imageContent
