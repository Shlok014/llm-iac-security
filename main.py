import openai, os, json, subprocess
from dotenv import load_dotenv

# ----------------------------
# Load environment variables
# ----------------------------
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")


# ----------------------------
# Helper: LLM call wrapper
# ----------------------------
def call_llm(prompt):
    try:
        response = openai.chat.completions.create(
            model="gpt-4o-mini",  # use gpt-4o-mini for speed/cost; change to gpt-4o if desired
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error calling LLM: {e}"


# ----------------------------
# Step 1: Detect vulnerabilities
# ----------------------------
def detect_vulnerabilities(code):
    prompt = f"""
    You are a DevSecOps expert. Analyze this Infrastructure-as-Code (Terraform) configuration 
    for vulnerabilities or misconfigurations. 

    Return a JSON array in this format:
    [{{"issue": "...", "severity": "...", "recommendation": "..."}}]

    Code:
    {code}
    """
    result = call_llm(prompt)
    # Attempt to parse JSON safely
    try:
        return json.loads(result)
    except json.JSONDecodeError:
        return {"raw_output": result}


# ----------------------------
# Step 2: Generate remediated code
# ----------------------------
def generate_fix(code, issues):
    prompt = f"""
    You are a DevSecOps assistant. Fix the following Infrastructure-as-Code (Terraform) securely 
    while addressing these issues:
    {issues}

    Return ONLY the corrected code (no markdown, no triple backticks, no explanations).
    
    Original Code:
    {code}
    """
    fixed = call_llm(prompt)
    # Remove markdown formatting if present
    fixed = fixed.replace("```hcl", "").replace("```terraform", "").replace("```", "").strip()
    return fixed


# ----------------------------
# Step 3: Validate with Checkov
# ----------------------------
def validate_with_checkov(file_path):
    try:
        cmd = ["python3", "-m", "checkov", "-f", file_path, "-o", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)

        output = result.stdout.strip()
        if not output:
            return {"message": "Checkov ran successfully but returned no JSON output (no issues found)."}
        
        # Sometimes Checkov returns non-JSON text before the JSON — fix that
        json_start = output.find("{")
        if json_start == -1:
            return {"message": "Checkov output not in JSON format", "raw_output": output}
        
        clean_output = output[json_start:]
        return json.loads(clean_output)
    except Exception as e:
        return {"error": f"Checkov validation failed: {e}"}


# ----------------------------
# Step 4: Main agentic workflow
# ----------------------------
def agentic_workflow(input_path):
    print("🧠 Step 1: Reading IaC code...")
    code = open(input_path).read()

    print("🔍 Step 2: Detecting vulnerabilities via LLM...")
    issues = detect_vulnerabilities(code)

    print("🛠️ Step 3: Generating secure version via LLM...")
    fixed_code = generate_fix(code, issues)

    os.makedirs("outputs/fixed", exist_ok=True)
    fixed_path = "outputs/fixed/fixed.tf"
    with open(fixed_path, "w") as f:
        f.write(fixed_code)

    print("⚙️ Step 4: Validating fix via Checkov...")
    validation = validate_with_checkov(fixed_path)

    print("✅ Done.")
    return {"issues": issues, "fixed_code": fixed_code, "validation": validation}


# ----------------------------
# Run the workflow
# ----------------------------
if __name__ == "__main__":
    input_file = "samples/s3_public.tf"  # Change this to your desired file
    result = agentic_workflow(input_file)
    print(json.dumps(result, indent=2))