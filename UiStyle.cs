using System;
using System.Drawing;
using System.Windows.Forms;

namespace DomainMembershipCheckRepair
{
    // Centralized visual contract for every WinForms surface.
    // Form-specific content can choose a logical minimum size, but typography,
    // common spacing, button sizing and status colors live here.
    internal static class UiStyle
    {
        internal const float LogicalDpi = 96F;

        internal static readonly Font BodyFont =
            CreateWindowsFont(9F, FontStyle.Regular);
        internal static readonly Font TitleFont =
            CreateWindowsFont(14F, FontStyle.Bold);
        internal static readonly Font ValueFont =
            CreateWindowsFont(9F, FontStyle.Bold);
        internal static readonly Font CaptionFont =
            CreateWindowsFont(8.25F, FontStyle.Regular);
        internal static readonly Font CaptionBoldFont =
            CreateWindowsFont(8.25F, FontStyle.Bold);

        // Intentional monospace exception for diagnostic/report text.
        internal static readonly Font MonospaceFont =
            new Font("Consolas", 9F, FontStyle.Regular, GraphicsUnit.Point);

        internal static readonly Size MainWindowSize = new Size(980, 820);
        internal static readonly Size MainWindowMinimumSize = new Size(640, 480);
        internal static readonly Size AccountConflictDialogSize = new Size(820, 560);
        internal static readonly Size AccountConflictDialogMinimumSize = new Size(620, 430);
        internal static readonly Size NewNameDialogSize = new Size(560, 230);
        internal static readonly Size NewNameDialogMinimumSize = new Size(430, 210);
        internal static readonly Size ComputerLookupDialogSize = new Size(560, 210);
        internal static readonly Size ComputerLookupDialogMinimumSize = new Size(430, 195);
        internal static readonly Size ReportDialogSize = new Size(900, 650);
        internal static readonly Size ReportDialogMinimumSize = new Size(560, 400);

        internal const int StandardButtonMinimumWidth = 96;
        internal const int StandardButtonHeight = 32;
        internal const int PreferredDcWidth = 285;
        internal const int PasswordWidth = 320;
        internal const int ActionTabsHeight = 300;
        internal const int ActionTabsMinimumHeight = 220;
        internal const float ActionAreaRowHeight = 320F;
        internal const float LogAreaRowHeight = 220F;
        internal static readonly Point ActionTabHeaderPadding = new Point(12, 4);

        internal const int ScreenMarginMinimum = 12;
        internal const int ScreenMarginMaximum = 32;
        internal const int ScreenMarginDivisor = 40;

        internal static readonly Padding ZeroPadding = new Padding(0);
        internal static readonly Padding TightPadding = new Padding(2);
        internal static readonly Padding SectionPadding = new Padding(6);
        internal static readonly Padding ButtonPadding = new Padding(8, 2, 8, 2);
        internal static readonly Padding RootPadding = new Padding(14);
        internal static readonly Padding DialogPadding = new Padding(16);
        internal static readonly Padding CompactDialogPadding = new Padding(12);
        internal static readonly Padding GroupPadding = new Padding(8, 6, 8, 8);
        internal static readonly Padding GroupMargin = new Padding(0, 0, 0, 6);
        internal static readonly Padding DcPanelMargin = new Padding(0, 2, 0, 0);
        internal static readonly Padding InlineLabelMargin = new Padding(0, 5, 8, 0);
        internal static readonly Padding InlineHintMargin = new Padding(8, 5, 0, 0);
        internal static readonly Padding StatusPanelMargin = new Padding(0, 3, 0, 0);
        internal static readonly Padding StatusBadgeMargin = new Padding(1);
        internal static readonly Padding StatusBadgePadding = new Padding(6, 5, 6, 5);
        internal static readonly Padding FooterMargin = new Padding(10, 7, 2, 1);
        internal static readonly Padding FileLogPathMargin = new Padding(12, 4, 0, 0);
        internal static readonly Padding ButtonRowPadding = new Padding(0, 6, 0, 0);
        internal static readonly Padding DialogWarningMargin = new Padding(0, 10, 0, 4);
        internal static readonly Padding DialogInputMargin = new Padding(0, 10, 0, 6);
        internal static readonly Padding InlineButtonMargin = new Padding(8, 0, 0, 0);

        internal static readonly Color StatusSuccessFore = Color.FromArgb(24, 94, 42);
        internal static readonly Color StatusSuccessBack = Color.FromArgb(226, 242, 230);
        internal static readonly Color StatusWarningFore = Color.FromArgb(120, 78, 0);
        internal static readonly Color StatusWarningBack = Color.FromArgb(255, 244, 204);
        internal static readonly Color StatusErrorFore = Color.FromArgb(151, 22, 22);
        internal static readonly Color StatusErrorBack = Color.FromArgb(252, 228, 228);
        internal static readonly Color StatusInfoFore = Color.FromArgb(25, 72, 120);
        internal static readonly Color StatusInfoBack = Color.FromArgb(228, 239, 250);

        internal static void ApplyForm(Form form)
        {
            if (form == null)
                return;

            form.AutoScaleDimensions = new SizeF(LogicalDpi, LogicalDpi);
            form.AutoScaleMode = AutoScaleMode.Dpi;
            form.Font = BodyFont;
        }

        internal static Button CreateButton(string text)
        {
            return CreateButton(text, StandardButtonMinimumWidth);
        }

        internal static Button CreateButton(string text, int minimumWidth)
        {
            Button button = new Button();
            button.Text = text ?? String.Empty;
            button.AutoSize = true;
            button.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            button.MinimumSize = new Size(
                Math.Max(StandardButtonMinimumWidth, minimumWidth),
                StandardButtonHeight);
            button.Padding = ButtonPadding;
            return button;
        }

        private static Font CreateWindowsFont(float size, FontStyle style)
        {
            Font system = SystemFonts.MessageBoxFont;
            return new Font(
                system.FontFamily,
                size,
                style,
                GraphicsUnit.Point);
        }
    }
}
