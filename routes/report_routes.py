from flask import Blueprint, render_template, send_file, send_from_directory, jsonify, request
import os
from datetime import datetime
from services.report_service import ReportService
from apscheduler.schedulers.background import BackgroundScheduler
from utils.auth_middleware import token_required

report_bp = Blueprint("reports", __name__)

@report_bp.route("/")
@token_required(allowed_roles=["OWNER","MANAGER"])
def reports_page():
    """Main reports page"""
    return render_template("reports.html")

# ============================================
# 1. LIST ALL REPORTS (for table)
# ============================================
@report_bp.get("/list")
def list_reports():
    """Returns list of all generated PDF reports for the table"""
    try:
        reports = ReportService.list_reports()
        return jsonify({
            "success": True,
            "reports": reports
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ============================================
# 2. GENERATE NEW REPORT
# ============================================
@report_bp.post("/generate")
def generate_report():
    """Generate a new inventory report (on-demand)"""
    try:
        data = request.get_json() or {}

        if "date" not in data or not str(data.get("date","")).strip():
            return jsonify({"success": False, "error": "Please select a date before generating a report."}), 400

        try:
            report_date = datetime.strptime(str(data["date"]).strip(), "%Y-%m-%d")
        except ValueError:
            return jsonify({"success": False, "error": "The date format is invalid. Please use the date picker."}), 400

        if report_date.date() > datetime.now().date():
            return jsonify({"success": False, "error": "You cannot generate a report for a future date."}), 400

        if report_date.year < 2000:
            return jsonify({"success": False, "error": "Please choose a date after 1 January 2000."}), 400

        result = ReportService.generate_inventory_pdf(report_date)

        return jsonify({
            "success": True,
            "message": "Report generated successfully",
            "report": {
                "filename": result["filename"],
                "date": result["date"],
                "report_date": result["date"],
                "total_items": result["summary"]["total_items"],
                "total_products": result["summary"]["total_products"],
                "total_value": result["summary"]["total_value"],
                "low_stock": result["summary"]["low_stock_items"]
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@report_bp.get("/download/<filename>")
def download_report(filename):
    try:
        # Security: block path traversal
        if ".." in filename or "/" in filename:
            return jsonify({"error": "Invalid filename"}), 400

        # Absolute path to reports folder
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        REPORTS_DIR = os.path.join(BASE_DIR, "reports")

        filepath = os.path.join(REPORTS_DIR, filename)

        if not os.path.exists(filepath):
            print("PDF NOT FOUND:", filepath)
            return jsonify({"error": "Report not found"}), 404

        download = request.args.get("download") == "true"

        return send_from_directory(
            directory=REPORTS_DIR,
            path=filename,
            mimetype="application/pdf",
            as_attachment=download
        )

    except Exception as e:
        print("PDF SERVING ERROR:", e)
        return jsonify({"error": str(e)}), 500


# ============================================
# 4. GET INVENTORY DATA (JSON)
# ============================================
@report_bp.get("/inventory")
def inventory_data():
    """Returns raw inventory data as JSON"""
    try:
        data = ReportService.inventory_report()
        
        # Calculate summary stats
        total_items = sum(item["qty"] for item in data)
        total_value = sum(item["total_value"] for item in data)
        low_stock = sum(1 for item in data if item["qty"] <= item["threshold"])
        
        return jsonify({
            "success": True,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_products": len(data),
                "total_items": total_items,
                "total_value": total_value,
                "low_stock_items": low_stock
            },
            "data": data
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ============================================
# 5. DELETE REPORT
# ============================================
@report_bp.delete("/delete/<filename>")
def delete_report(filename):
    """Delete a report file"""
    try:
        success = ReportService.delete_report(filename)
        if success:
            return jsonify({
                "success": True,
                "message": f"Report '{filename}' deleted successfully"
            })
        else:
            return jsonify({"success": False, "error": "Failed to delete report"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ============================================
# 6. MANUALLY TRIGGER MONTHLY REPORT
# ============================================
@report_bp.post("/generate/monthly")
def trigger_monthly_report():
    """Manually trigger a monthly report (for testing)"""
    try:
        # Set date to 1st of current month
        report_date = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        result = ReportService.generate_inventory_pdf(report_date)
        
        return jsonify({
            "success": True,
            "message": "Monthly report generated",
            "report": {
                "filename": result["filename"],
                "date": result["date"]
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ============================================
# 7. GET REPORT DETAILS
# ============================================
@report_bp.get("/details/<filename>")
def report_details(filename):
    """Get metadata about a specific report"""
    try:
        reports = ReportService.list_reports()
        target_report = next((r for r in reports if r["filename"] == filename), None)
        
        if not target_report:
            return jsonify({"success": False, "error": "Report not found"}), 404
        
        return jsonify({
            "success": True,
            "report": target_report
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ============================================
# MONTHLY AUTOMATIC REPORT SCHEDULER
# ============================================
def generate_monthly_automatic_report():
    """Function called by scheduler on 1st of every month"""
    print(f"[{datetime.now()}] Generating monthly automatic report...")
    
    # Set date to 1st of current month
    report_date = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    try:
        result = ReportService.generate_inventory_pdf(report_date)
        print(f"[{datetime.now()}] Monthly report generated: {result['filename']}")
    except Exception as e:
        print(f"[{datetime.now()}] Error generating monthly report: {e}")

# ============================================
# INITIALIZATION
# ============================================
def init_report_scheduler():
    """Initialize the scheduler for automatic monthly reports"""
    try:
        scheduler = BackgroundScheduler()
        
        # Schedule monthly report on 1st day of month at 6:00 AM
        scheduler.add_job(
            generate_monthly_automatic_report,
            'cron',
            day=1,
            hour=6,
            minute=0,
            name="monthly_inventory_report"
        )
        
        scheduler.start()
        print("[Report Scheduler] Started - Monthly reports will generate on 1st of each month at 6:00 AM")
        
        return scheduler
    except Exception as e:
        print(f"[Report Scheduler] Error: {e}")
        return None

# Create reports directory if it doesn't exist
os.makedirs("reports", exist_ok=True)