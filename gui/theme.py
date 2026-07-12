"""
TOP RECON — dark cyber theme.

A dark operations palette: near-black background, teal/green accents, thin panel
borders, monospace metrics. One global stylesheet plus named colour constants the
custom-painted widgets (graph, gauges) read directly.
"""

from __future__ import annotations

# --- palette ---------------------------------------------------------------
BG_DEEP      = "#060a11"     # window background
BG_PANEL     = "#0b111b"     # panel fill
BG_PANEL_HI  = "#0e1622"     # slightly raised (tables, rows)
BORDER       = "#16212f"     # panel border
BORDER_HI    = "#1d2c3e"     # brighter border / hover

ACCENT       = "#00e676"     # primary neon green
ACCENT_TEAL  = "#26c6da"     # secondary teal
ACCENT_DIM   = "#0f8a52"

TEXT_BRIGHT  = "#d6e4ee"     # headline text
TEXT         = "#9fb3c2"     # body text
TEXT_MUTED   = "#5f7688"     # captions
TEXT_FAINT   = "#3d4f5e"     # awaiting / disabled

RUNNING      = "#00e676"
QUEUED       = "#e0a441"
NEEDS_KEY    = "#c77dff"
MISSING      = "#5f7688"
ERRORC       = "#ff5b6e"

SEV = {
    "critical": "#ff4d5e",
    "high":     "#ff8a3c",
    "medium":   "#e3c341",
    "low":      "#3fd07f",
    "info":     "#3aa0ff",
}

FONT_MONO = "'JetBrains Mono','Cascadia Code','Consolas','Courier New',monospace"
FONT_UI   = "'Segoe UI','Inter',sans-serif"


def stylesheet() -> str:
    return f"""
    QWidget {{
        background: {BG_DEEP};
        color: {TEXT};
        font-family: {FONT_UI};
        font-size: 12px;
    }}
    QToolTip {{
        background: {BG_PANEL_HI}; color: {TEXT_BRIGHT};
        border: 1px solid {BORDER_HI}; padding: 4px 8px;
    }}

    /* --- panels --- */
    QFrame#panel {{
        background: {BG_PANEL};
        border: 1px solid {BORDER};
        border-radius: 6px;
    }}
    QFrame#panelHeader {{ background: transparent; border: none; }}
    QLabel#panelTitle {{
        color: {ACCENT_TEAL};
        font-family: {FONT_MONO};
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 2px;
    }}
    QLabel#panelBadge {{
        color: {ACCENT_TEAL};
        font-family: {FONT_MONO};
        font-size: 11px;
        font-weight: 700;
    }}
    QLabel#viewAll {{
        color: {ACCENT_TEAL}; font-family: {FONT_MONO};
        font-size: 9px; font-weight: 700; letter-spacing: 1px;
    }}
    QLabel#viewAll:hover {{ color: {ACCENT}; }}
    QLabel#sectionLabel {{
        color: {TEXT_MUTED}; font-family: {FONT_MONO};
        font-size: 10px; letter-spacing: 1px;
    }}

    /* --- frameless window frame --- */
    QMainWindow#mainWindow {{ border: 1px solid {BORDER_HI}; }}
    QWidget#windowFrame {{ background: {BG_DEEP}; border: 1px solid {BORDER_HI};
                           border-radius: 0px; }}

    /* --- title bar + window controls --- */
    QFrame#titleBar {{ background: {BG_PANEL}; border-bottom: 1px solid {BORDER}; }}
    QPushButton#newRecon {{ background: #0d2a1c; color: {ACCENT};
        border: 1px solid {ACCENT_DIM}; border-radius: 5px; padding: 7px 16px;
        font-family: {FONT_MONO}; font-size: 11px; font-weight: 800; letter-spacing: 1px; }}
    QPushButton#newRecon:hover {{ background: #12472c; border-color: {ACCENT}; }}
    QPushButton#keysBtn {{ background: transparent; color: {TEXT_MUTED};
        border: 1px solid {BORDER_HI}; border-radius: 5px; padding: 7px 12px;
        font-family: {FONT_MONO}; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
    QPushButton#keysBtn:hover {{ color: {ACCENT_TEAL}; border-color: {ACCENT_TEAL}; }}
    QPushButton#winBtn {{ background: transparent; color: {TEXT_MUTED};
        border: none; border-radius: 5px; font-size: 13px; font-weight: 700; }}
    QPushButton#winBtn:hover {{ background: {BG_PANEL_HI}; color: {TEXT_BRIGHT}; }}
    QPushButton#winClose {{ background: transparent; color: {TEXT_MUTED};
        border: none; border-radius: 5px; font-size: 12px; font-weight: 700; }}
    QPushButton#winClose:hover {{ background: #c0392b; color: #ffffff; }}

    /* --- frameless dialogs --- */
    QFrame#dlgFrame {{ background: {BG_DEEP}; border: 1px solid {BORDER_HI}; }}
    QFrame#dlgTitle {{ background: {BG_PANEL}; border-bottom: 1px solid {BORDER}; }}
    QLabel#dlgTitleText {{ color: {ACCENT_TEAL}; font-family: {FONT_MONO};
        font-size: 11px; font-weight: 700; letter-spacing: 2px; }}

    /* --- top bar --- */
    QFrame#topBar {{ background: {BG_PANEL}; border-bottom: 1px solid {BORDER}; }}
    QLabel#appName {{
        color: {ACCENT}; font-family: {FONT_MONO};
        font-size: 20px; font-weight: 800; letter-spacing: 3px;
    }}
    QLabel#appTag {{ color: {TEXT_MUTED}; font-family: {FONT_MONO}; font-size: 9px;
                     letter-spacing: 2px; }}
    QLabel#metricValue {{ color: {TEXT_BRIGHT}; font-family: {FONT_MONO};
                          font-size: 15px; font-weight: 700; }}
    QLabel#metricValueGreen {{ color: {ACCENT}; font-family: {FONT_MONO};
                          font-size: 15px; font-weight: 700; }}
    QLabel#metricLabel {{ color: {TEXT_MUTED}; font-family: {FONT_MONO};
                          font-size: 8px; letter-spacing: 2px; }}

    /* --- footer --- */
    QFrame#footer {{ background: {BG_PANEL}; border-top: 1px solid {BORDER}; }}
    QFrame#footerBar {{ background: {BG_PANEL}; }}
    QLabel#footLabel {{ color: {TEXT_MUTED}; font-family: {FONT_MONO};
        font-size: 8px; font-weight: 700; letter-spacing: 1px; }}
    QLabel#footValue {{ color: {TEXT_BRIGHT}; font-family: {FONT_MONO};
        font-size: 12px; font-weight: 700; }}
    QLabel#footValueGreen {{ color: {ACCENT}; font-family: {FONT_MONO};
        font-size: 12px; font-weight: 700; }}
    QFrame#banner {{ background: #0d1a12; border: 1px solid {ACCENT_DIM};
                     border-radius: 4px; }}
    QLabel#bannerText {{ color: {ACCENT}; font-family: {FONT_MONO};
                         font-size: 11px; letter-spacing: 1px; }}

    /* --- lists / tables --- */
    QListWidget, QTableWidget, QTreeWidget {{
        background: transparent; border: none; outline: 0;
        font-family: {FONT_MONO}; font-size: 11px;
    }}
    QTableWidget::item, QListWidget::item {{ padding: 2px 4px; }}
    QListWidget::item:hover {{ background: {BG_PANEL_HI}; }}
    QListWidget::item:selected, QTableWidget::item:selected {{
        background: #0d2a1c; color: {TEXT_BRIGHT};
    }}
    QHeaderView::section {{
        background: transparent; color: {TEXT_MUTED};
        border: none; border-bottom: 1px solid {BORDER};
        padding: 4px; font-family: {FONT_MONO}; font-size: 9px; letter-spacing: 1px;
    }}
    QTableWidget {{ gridline-color: transparent; }}

    /* --- buttons --- */
    QPushButton {{
        background: {BG_PANEL_HI}; color: {TEXT};
        border: 1px solid {BORDER_HI}; border-radius: 4px;
        padding: 5px 12px; font-family: {FONT_MONO}; font-size: 11px;
    }}
    QPushButton:hover {{ border-color: {ACCENT_DIM}; color: {TEXT_BRIGHT}; }}
    QPushButton:checked {{ background: #0d2a1c; color: {ACCENT};
                           border-color: {ACCENT_DIM}; }}
    QPushButton#primary {{ background: #0d2a1c; color: {ACCENT};
                           border: 1px solid {ACCENT_DIM}; font-weight: 700; }}
    QPushButton#primary:hover {{ background: #123a26; }}
    QPushButton#pauseBtn {{ color: {QUEUED}; border-color: #4a3a1a; font-weight: 700; }}
    QPushButton#pauseBtn:hover {{ border-color: {QUEUED}; background: #241c0a; }}
    QPushButton#stopBtn {{ color: {ERRORC}; border-color: #4a1e22; font-weight: 700; }}
    QPushButton#stopBtn:hover {{ border-color: {ERRORC}; background: #2a1113; }}
    QPushButton#stopBtn:disabled, QPushButton#pauseBtn:disabled {{
        color: {TEXT_FAINT}; border-color: {BORDER}; }}
    QPushButton:disabled {{ color: {TEXT_FAINT}; border-color: {BORDER}; }}

    /* --- inputs --- */
    QLineEdit, QComboBox, QSpinBox {{
        background: {BG_DEEP}; color: {TEXT_BRIGHT};
        border: 1px solid {BORDER_HI}; border-radius: 4px; padding: 6px 8px;
        font-family: {FONT_MONO}; selection-background-color: {ACCENT_DIM};
    }}
    QLineEdit:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
    QCheckBox {{ color: {TEXT}; font-size: 12px; spacing: 8px; }}
    QCheckBox::indicator {{ width: 16px; height: 16px; border: 1px solid {BORDER_HI};
                            border-radius: 3px; background: {BG_DEEP}; }}
    QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}

    /* --- scrollbars (thin HUD rails) --- */
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px 0; }}
    QScrollBar::handle:vertical {{ background: {BORDER_HI}; border-radius: 5px;
                                   min-height: 28px; }}
    QScrollBar::handle:vertical:hover {{ background: {ACCENT_TEAL}; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 0 2px; }}
    QScrollBar::handle:horizontal {{ background: {BORDER_HI}; border-radius: 5px;
                                     min-width: 28px; }}
    QScrollBar::handle:horizontal:hover {{ background: {ACCENT_TEAL}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

    /* --- bottom analysis tabs (full, uncramped titles) --- */
    QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 6px;
                        background: {BG_PANEL}; top: -1px; }}
    QTabBar {{ qproperty-drawBase: 0; }}
    QTabBar::tab {{ background: transparent; color: {TEXT_MUTED};
                    padding: 8px 20px; margin-right: 2px; min-width: 96px;
                    font-family: {FONT_MONO}; font-size: 10px; font-weight: 700;
                    letter-spacing: 1px; border: 1px solid transparent;
                    border-top-left-radius: 5px; border-top-right-radius: 5px; }}
    QTabBar::tab:hover {{ color: {TEXT_BRIGHT}; background: {BG_PANEL_HI}; }}
    QTabBar::tab:selected {{ color: {ACCENT}; background: {BG_PANEL};
                    border: 1px solid {BORDER}; border-bottom: 2px solid {ACCENT}; }}

    /* --- left icon rail --- */
    QFrame#iconRail {{ background: {BG_PANEL}; border-right: 1px solid {BORDER}; }}
    QPushButton#railBtn {{ background: transparent; color: {TEXT_MUTED};
        border: none; border-left: 2px solid transparent; border-radius: 0px;
        font-size: 17px; padding: 0px; }}
    QPushButton#railBtn:hover {{ color: {ACCENT_TEAL}; background: {BG_PANEL_HI}; }}
    QPushButton#railBtn:checked {{ color: {ACCENT}; background: #0d1f17;
        border-left: 2px solid {ACCENT}; }}

    /* --- sub-header (authorised scope strip) --- */
    QFrame#subHeader {{ background: {BG_PANEL}; border-bottom: 1px solid {BORDER}; }}
    QLabel#subMuted {{ color: {TEXT_MUTED}; font-family: {FONT_MONO};
        font-size: 10px; letter-spacing: 1px; }}
    QLabel#subKey {{ color: {TEXT_FAINT}; font-family: {FONT_MONO};
        font-size: 9px; letter-spacing: 2px; }}
    QFrame#scopeChip {{ background: #0d1a12; border: 1px solid {ACCENT_DIM};
        border-radius: 4px; }}
    QLabel#scopeChipText {{ color: {ACCENT}; font-family: {FONT_MONO};
        font-size: 11px; font-weight: 700; }}
    QLabel#pillOn {{ color: {ACCENT}; background: #0d2a1c; border: 1px solid {ACCENT_DIM};
        border-radius: 3px; padding: 3px 10px; font-family: {FONT_MONO};
        font-size: 9px; font-weight: 700; letter-spacing: 1px; }}
    QLabel#pillOff {{ color: {TEXT_MUTED}; background: transparent;
        border: 1px solid {BORDER_HI}; border-radius: 3px; padding: 3px 10px;
        font-family: {FONT_MONO}; font-size: 9px; font-weight: 700; letter-spacing: 1px; }}
    QPushButton#configBtn {{ background: transparent; color: {ACCENT_TEAL};
        border: 1px solid {BORDER_HI}; border-radius: 4px; padding: 5px 14px;
        font-family: {FONT_MONO}; font-size: 10px; font-weight: 700; letter-spacing: 1px; }}
    QPushButton#configBtn:hover {{ border-color: {ACCENT_TEAL}; background: {BG_PANEL_HI}; }}

    /* --- graph focus bar (isolate / centralize a node) --- */
    QFrame#focusBar {{ background: #0c1620; border: 1px solid {BORDER_HI};
        border-radius: 5px; }}
    QLabel#focusChip {{ color: {ACCENT_TEAL}; font-family: {FONT_MONO};
        font-size: 12px; font-weight: 700; }}
    QLabel#focusHint {{ color: {TEXT_MUTED}; font-family: {FONT_MONO}; font-size: 9px; }}
    QPushButton#focusBtn {{ background: {BG_PANEL_HI}; color: {TEXT};
        border: 1px solid {BORDER_HI}; border-radius: 4px; padding: 5px 12px;
        font-family: {FONT_MONO}; font-size: 10px; font-weight: 700; }}
    QPushButton#focusBtn:hover {{ color: {TEXT_BRIGHT}; border-color: {ACCENT_TEAL}; }}
    QPushButton#focusBtn:checked {{ background: #0d2a1c; color: {ACCENT};
        border-color: {ACCENT}; }}
    """
