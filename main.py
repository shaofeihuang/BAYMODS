from utils import *

st.session_state['af_modifier_input'] = 0.1 # Attack Feasibility Modifier
st.session_state['date_input'] = "2024-01-01" # Default date input

if __name__ == "__main__":
    with st.sidebar:
        st.image("logo.png")
        st.title("BAYMODS - CPS Risk Assessment")
        st.markdown("""
        **BAYMODS** is a CPS risk assessment tool using Bayesian Networks.
        
        **Instructions:**
        1. Upload your AutomationML file.
        2. Select the attacker ID from the dropdown.
        3. Click on "Compute Risk Score".
        
        **Note:** Ensure that your AutomationML file is correctly formatted.
        """)
        st.session_state['start_node'] = st.selectbox(
            "Attacker ID in the system model",
            ("Attacker", "[U01] Attacker", "User"),
            index=0,
            placeholder="Select or enter attacker ID",
            accept_new_options=True,
        )

    tab1, tab2 = st.tabs(["Probabilistic Risk Analysis", "Multi-Objective Optimisation"])

    with tab1:
        st.title("Probabilistic Analysis")
        uploaded_aml = st.file_uploader("Upload your AutomationML file", type=["aml", "xml"])

        if uploaded_aml is not None:
                aml_content = uploaded_aml.read().decode("utf-8")
                st.session_state['aml_file'] = aml_content
                st.success("AutomationML file uploaded successfully.")

        if st.button("Compute Risk Score"):
            load_model_attributes()

            compute_risk_score()

            st.success("Risk assessment completed!")

    with tab2:
        st.title("Multi-Objective Optimisation")
        n_trials = st.number_input("Number of Trials per Run", min_value=10, max_value=1000, value=100, step=10)
        n_runs = st.number_input("Number of Concurrent Runs", min_value=1, max_value=20, value=5, step=1)
        graph = st.checkbox("Show Optimisation Graph", value=True)
        verbose = st.checkbox("Verbose Output", value=True)
        tmp_output = "output.csv"

        if ('aml_data' in st.session_state):
            n_vulns = len(st.session_state['aml_data'].VulnerabilityinSystem)
            
        if 'futures' not in st.session_state:
            st.session_state['futures'] = None

        if st.button("Start Optimisation"):
            if os.path.exists(tmp_output):
                os.remove(tmp_output) # clean up previous output file

            start_time = datetime.now()

            with ProcessPoolExecutor() as executor:
                futures = [
                    executor.submit(run_study, n_trials, n_vulns, graph, verbose, tmp_output)
                    for run in range(n_runs)
                ]
                for future in futures:
                    future.result()  # Wait for all processes to complete

            if st.session_state['futures'] is not None:
                all_done = all(f.done() for f in st.session_state['futures'])

            if all_done:
                end_time = datetime.now()
                total_time = end_time - start_time  # Compute duration
                hours, remainder = divmod(total_time.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                st.success("Optimisation completed!")
                st.write(f"Total execution time: {hours} hours {minutes} minutes {seconds} seconds")