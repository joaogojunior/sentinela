import sys
import dashboard_utils

if __name__ == "__main__":
    app = dashboard_utils.QApplication(sys.argv)
    window = dashboard_utils.Dashboard.inicia_se_for_a_primeira()
    if window:
        window.show()
        status = app.exec()
        sys.exit(status)
    sys.exit(0)