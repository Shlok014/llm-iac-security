import streamlit as st
import json, re, ast, os
import pandas as pd
from main import detect_vulnerabilities, generate_fix, validate_with_checkov

# ----------------------------
# Streamlit Page Config
# ----------------------------
st.set_page_config(
    page_title="LLM Agentic Workflow – IaC Security",
    page_icon="🧠",
    layout="wide"
)

# ----------------------------
# Header
# ----------------------------
st.title("🧠 LLM Agentic Workflow for IaC Vulnerability Detection & Remediation")
st.caption("Automated vulnerability detection, remediation, and validation in Infrastructure-as-Code using an LLM and Checkov ⚙️")

# ----------------------------
# Helper UI Function
# ----------------------------
def render_step(step_text, color="#9e9e9e"):
    """Render colored step boxes for visual workflow progress"""
    html = f"""
    <div style='padding:10px;border-radius:6px;
    background-color:{color};
    color:white;font-weight:600;text-align:center;margin-bottom:6px;'>{step_text}</div>
    """
    return html


# ----------------------------
# Main Logic
# ----------------------------
uploaded_file = st.file_uploader("📤 Upload your IaC file", type=["tf", "Dockerfile", "yml", "yaml"])

if uploaded_file is not None:
    code = uploaded_file.read().decode("utf-8")
    st.subheader("📄 Uploaded Code")
    st.code(code, language="hcl")

    step_box = st.empty()
    progress = st.progress(0)
    log_box = st.empty()

    if st.button("🚀 Run Analysis (Agentic Workflow)"):
        # Reset workspace
        temp_path = f"temp_{uploaded_file.name}"
        try:
            os.remove(temp_path)
        except Exception:
            pass

        # Save uploaded file
        with open(temp_path, "w") as f:
            f.write(code)

        # ----------------------------
        # Step 1: Detect Vulnerabilities
        # ----------------------------
        step_box.markdown(render_step("🔍 Step 1: Detecting vulnerabilities via LLM...", "#f4b400"), unsafe_allow_html=True)
        try:
            issues = detect_vulnerabilities(code)
            log_box.info("✅ Step 1 complete: Vulnerability detection finished.")
        except Exception as e:
            issues = {"raw_output": ""}
            log_box.error(f"Step 1 failed: {e}")
        progress.progress(33)

        # ----------------------------
        # Step 2: Generate Remediation
        # ----------------------------
        step_box.markdown(render_step("🛠️ Step 2: Generating remediated code via LLM...", "#f4b400"), unsafe_allow_html=True)
        try:
            fixed_code = generate_fix(code, issues)
            if isinstance(fixed_code, str):
                fixed_code = fixed_code.replace("```hcl", "").replace("```terraform", "").replace("```", "").strip()
            log_box.info("✅ Step 2 complete: Remediation generated.")
        except Exception as e:
            fixed_code = ""
            log_box.error(f"Step 2 failed: {e}")
        progress.progress(66)

        # Save fixed file for validation
        os.makedirs("outputs/fixed", exist_ok=True)
        fixed_path = "outputs/fixed/fixed.tf"
        try:
            with open(fixed_path, "w") as f:
                f.write(fixed_code)
        except Exception as e:
            log_box.error(f"⚠️ Failed to write fixed file: {e}")

        # ----------------------------
        # Step 3: Validate Fix (Checkov)
        # ----------------------------
        step_box.markdown(render_step("⚙️ Step 3: Validating fix via Checkov...", "#0f9d58"), unsafe_allow_html=True)
        try:
            validation = validate_with_checkov(fixed_path)
            log_box.info("✅ Step 3 complete: Validation finished.")
        except Exception as e:
            validation = {"error": f"Validation failed: {e}"}
            log_box.error(f"Step 3 failed: {e}")
        progress.progress(100)

        # ----------------------------
        # Done
        # ----------------------------
        step_box.markdown(render_step("✅ Workflow Completed Successfully!", "#34a853"), unsafe_allow_html=True)
        st.success("✅ Agentic workflow completed successfully!")

        # ============================================================
        # 🔍 Vulnerability Report (Final Parser + Color Code)
        # ============================================================
        st.subheader("🔍 Vulnerability Report")

        try:
            # 1️⃣ Extract raw text safely
            if isinstance(issues, dict) and "raw_output" in issues:
                raw = issues["raw_output"]
            elif isinstance(issues, str):
                raw = issues
            else:
                raw = json.dumps(issues)

            # 2️⃣ Clean and extract JSON block
            raw = raw.strip()
            json_block = re.search(r"```json(.*?)```", raw, re.DOTALL)
            if json_block:
                raw = json_block.group(1).strip()
            else:
                # fallback: find JSON array boundaries
                start = raw.find('[')
                end = raw.rfind(']')
                if start != -1 and end != -1:
                    raw = raw[start:end + 1].strip()

            # 3️⃣ Normalize and parse JSON
            raw = raw.replace("\\n", "\n").replace("\\t", "\t").strip()
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = ast.literal_eval(raw)

            # ✅ Ensure list format
            if isinstance(parsed, dict):
                parsed = [parsed]

            # ✅ Build DataFrame
            df = pd.DataFrame(parsed)

            # ✅ Highlight function with Critical
            def highlight_severity(val):
                if isinstance(val, str):
                    v = val.lower()
                    if "critical" in v:
                        return "background-color:#b30000; color:white; font-weight:700;"
                    if "high" in v:
                        return "background-color:#ff6666; color:white;"
                    if "medium" in v:
                        return "background-color:#fff2cc; color:#a86f00;"
                    if "low" in v:
                        return "background-color:#d9ead3; color:#005500;"
                return ""

            st.dataframe(df.style.map(highlight_severity, subset=["severity"]), width="stretch")

            # ✅ Summary line with Critical
            severity_counts = df["severity"].astype(str).str.lower().value_counts()
            st.markdown(
                f"**Summary:** 🔥 Critical = {severity_counts.get('critical',0)} "
                f"🔴 High = {severity_counts.get('high',0)} "
                f"🟠 Medium = {severity_counts.get('medium',0)} "
                f"🟢 Low = {severity_counts.get('low',0)}"
            )

        except Exception as e:
            st.warning("⚠️ Could not parse LLM response as structured JSON.")
            st.text_area("Raw LLM Output", str(issues))
            st.text(f"Error: {e}")

        # ============================================================
        # 🧾 Original vs Remediated Code
        # ============================================================
        st.subheader("🧾 Original vs Remediated Code")
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Original Code:**")
            st.code(code, language="hcl")

        with col2:
            st.markdown("**Remediated Code:**")
            st.code(fixed_code or "No fixed code generated", language="hcl")

        # ============================================================
        # ⚙️ Validation Summary
        # ============================================================
        st.subheader("⚙️ Validation Result (Checkov)")
        st.json(validation)

        # ============================================================
        # 📥 Downloadable JSON Report
        # ============================================================
        st.subheader("📥 Download Report")
        report_data = {
            "issues": issues,
            "fixed_code": fixed_code,
            "validation": validation
        }
        report_json = json.dumps(report_data, indent=2)
        st.download_button(
            label="💾 Download JSON Report",
            data=report_json,
            file_name="iac_security_report.json",
            mime="application/json"
        )

else:
    st.info("👆 Upload a Terraform or Dockerfile to begin analysis.")