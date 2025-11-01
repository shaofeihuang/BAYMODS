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
            print (st.session_state.keys())
            saved_session_state = {
                key: st.session_state[key]
                for key in st.session_state.keys()
            }
            print (saved_session_state.keys())
            with open("session.json", "wb") as f:
                pickle.dump(saved_session_state, f)

            compute_risk_score()

            st.success("Risk assessment completed!")

    with tab2:
        st.title("Multi-Objective Optimisation")
        n_trials = st.number_input("Number of Trials per Run", min_value=10, max_value=1000, value=100, step=10)
        n_runs = st.number_input("Number of Concurrent Runs", min_value=1, max_value=20, value=5, step=1)
        if 'aml_data' in st.session_state:
            st.write("Number of vulnerabilitiies in BN: {}".format(len(st.session_state['aml_data'].VulnerabilityinSystem)) )
        graph = st.checkbox("Show Optimisation Graph", value=False)
        verbose = st.checkbox("Verbose Output", value=True)
        tmp_output = "output.csv"

        if st.button("Start Optimisation"):
            if os.path.exists(tmp_output):
                os.remove(tmp_output) # clean up previous output file

            start_time = datetime.now()

            with ProcessPoolExecutor() as executor:
                futures = [
                    executor.submit(run_study, n_trials, graph, verbose, tmp_output)
                    for run in range(n_runs)
                ]
                for future in futures:
                    future.result()  # Wait for all processes to complete

            all_done = True

            if all_done:
                end_time = datetime.now()
                total_time = end_time - start_time  # Compute duration
                hours, remainder = divmod(total_time.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                st.success("Optimisation completed!")
                st.write(f"Total execution time: {hours} hours {minutes} minutes {seconds} seconds")
                
                df = pd.read_csv(tmp_output, header=None)

                v_headers = [f"V{str(i + 1).zfill(2)}" for i in range(len(df.columns) - 3)]
                new_header_row = v_headers + ["Likelihood", "Impact", "Availability"]
                df.columns = new_header_row
                df.insert(0, "Run ID", range(1, len(df) + 1))

                st.subheader("Optimisation Results")
                st.write("The table below shows the results of the multi-objective optimisation." \
                "Each row represents a Pareto-optimal configuration of mitigation priorities and the corresponding likelihood, impact, and availability probabilities.")
                st.dataframe(df)

                v_columns = df.columns[1:-3]
                v_data = df[v_columns].apply(pd.to_numeric, errors='coerce')
                v_means = v_data.mean()
                st.bar_chart(v_means)