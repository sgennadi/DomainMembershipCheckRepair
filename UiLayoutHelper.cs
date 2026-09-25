using System;
using System.Drawing;
using System.Windows.Forms;

namespace DomainMembershipCheckRepair
{
    internal static class UiLayoutHelper
    {
        internal static void EnableScreenAwareSizing(
            Form form,
            Size minimumDeviceSize)
        {
            if (form == null)
                return;

            form.MinimumSize = Size.Empty;

            form.Shown += delegate
            {
                FitToWorkingArea(form, minimumDeviceSize);
            };

            form.DpiChanged += delegate
            {
                if (form.IsHandleCreated)
                {
                    form.BeginInvoke(new MethodInvoker(delegate
                    {
                        FitToWorkingArea(form, minimumDeviceSize);
                    }));
                }
            };
        }

        internal static Size CalculateFittedSize(
            Size requested,
            Size workingArea,
            int margin,
            Size minimum)
        {
            int safeMargin = Math.Max(0, margin);
            int maxWidth = Math.Max(1, workingArea.Width - (safeMargin * 2));
            int maxHeight = Math.Max(1, workingArea.Height - (safeMargin * 2));

            int width = Math.Min(Math.Max(1, requested.Width), maxWidth);
            int height = Math.Min(Math.Max(1, requested.Height), maxHeight);

            int minWidth = Math.Min(Math.Max(1, minimum.Width), maxWidth);
            int minHeight = Math.Min(Math.Max(1, minimum.Height), maxHeight);

            width = Math.Max(width, minWidth);
            height = Math.Max(height, minHeight);

            return new Size(width, height);
        }

        private static void FitToWorkingArea(
            Form form,
            Size minimumDeviceSize)
        {
            if (form == null || form.WindowState == FormWindowState.Minimized)
                return;

            Screen screen = Screen.FromControl(form);
            Rectangle working = screen.WorkingArea;
            if (working.Width <= 0 || working.Height <= 0)
                return;

            int margin = Math.Max(12, Math.Min(32, working.Width / 40));
            Size fitted = CalculateFittedSize(
                form.Size,
                working.Size,
                margin,
                minimumDeviceSize);

            form.MinimumSize = new Size(
                Math.Min(minimumDeviceSize.Width, fitted.Width),
                Math.Min(minimumDeviceSize.Height, fitted.Height));

            if (form.WindowState == FormWindowState.Normal)
            {
                if (form.Width != fitted.Width || form.Height != fitted.Height)
                    form.Size = fitted;

                int left = form.Left;
                int top = form.Top;

                if (left < working.Left || left + form.Width > working.Right)
                    left = working.Left + Math.Max(0, (working.Width - form.Width) / 2);

                if (top < working.Top || top + form.Height > working.Bottom)
                    top = working.Top + Math.Max(0, (working.Height - form.Height) / 2);

                form.Location = new Point(left, top);
            }
        }
    }
}
