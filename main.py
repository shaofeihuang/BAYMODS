from utils import *

st.session_state['af_modifier_input'] = 0.1 # Attack Feasibility Modifier
st.session_state['date_input'] = "2024-01-01" # Default date input

if __name__ == "__main__":
    with st.sidebar:
        st.image("logo.png")
        st.title("BAYMODS (Bayesian and Multi-Objective Decision Support)")
        st.markdown("""
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
        st.title("Probabilistic Risk Analysis")
        st.markdown("""
        This module performs probabilistic risk analysis (single trial) using Bayesian Networks to compute the likelihood of successful attacks, serious impacts, and overall risk scores based on the provided system model.
        """)
        st.markdown("""
        **Note:** If you encounter "ValueError: Node Attacker not in graph", please ensure that the Attacker ID you selected matches the one defined in your AutomationML file.
        """)
        st.markdown("""---""")

        uploaded_aml = st.file_uploader("Upload your AutomationML file", type=["aml", "xml"])

        if uploaded_aml is not None:
                aml_content = uploaded_aml.read().decode("utf-8")
                st.session_state['aml_file'] = aml_content
                st.success("AutomationML file uploaded successfully.")

        if st.button("Compute Risk Score"):
            load_model_attributes()
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
        st.markdown("""
        This module performs multi-objective optimisation using Optuna to identify Pareto-optimal mitigation strategies that balance likelihood reduction, impact minimisation, and availability maximisation.
        """)
        st.markdown("""---""")
        n_trials = st.number_input("Number of Trials per Run", min_value=10, max_value=10000, value=1000, step=10)
        n_runs = st.number_input("Number of Optimisation Runs", min_value=1, max_value=20, value=1, step=1)
        if 'aml_data' in st.session_state:
            st.write("Number of vulnerabilitiies detected in model: {}".format(len(st.session_state['aml_data'].VulnerabilityinSystem)) )
        graph = st.checkbox("Show Optimisation Graph", value=False)
        verbose = st.checkbox("Verbose Console Output", value=True)

        if st.button("Start Optimisation"):
            files_to_remove = glob.glob("results-*.csv")
            for file_path in files_to_remove:
                if os.path.exists(file_path):
                    os.remove(file_path)

            files_to_remove = glob.glob("202*.txt")
            for file_path in files_to_remove:
                if os.path.exists(file_path):
                    os.remove(file_path)

            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            st.session_state['output_filename'] = f"results-{timestamp}.csv"

            start_time = datetime.now()

            with st.spinner("Optimisation in progress... This may take several minutes."):
                with ProcessPoolExecutor() as executor:
                    futures = [
                        executor.submit(run_study, n_trials, graph, verbose, st.session_state['output_filename'])
                        for run in range(n_runs)
                    ]
                    for future in futures:
                        future.result()  # Wait for all processes to complete

            total_time = datetime.now() - start_time  # Compute duration
            hours, remainder = divmod(total_time.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            st.success(f"Optimisation completed! Total execution time: {hours} hours {minutes} minutes {seconds} seconds")
            st.session_state['optimisation_done'] = True

        if st.session_state.get('optimisation_done', False):
            st.markdown("""---""")
            st.subheader("Optimisation Results")
            st.info("The table below summarises the mitigation priority values assigned to each vulnerability for the most Pareto-optimal trial in each optimisation run, along with the corresponding Likelihood, Impact, and Availability metrics.")

            df = pd.read_csv(st.session_state['output_filename'], header=None)
            v_headers = [f"V{str(i + 1).zfill(2)}" for i in range(len(df.columns) - 4)]
            new_header_row = v_headers + ["Best Trial ID", "Likelihood", "Impact", "Availability"]
            df.columns = new_header_row
            df.insert(0, "Run ID", range(1, len(df) + 1))
            st.dataframe(df)

            st.markdown("""
            **Table explanation:**
            - Run ID: Unique identifier for each optimisation run.
            - V01, V02, ...: Mitigation priority values for each vulnerability (0 = highest priority, 1 = second highest, etc.).
            """)

            st.info("The bar chart below displays the average mitigation priority assigned to each vulnerability across Pareto-optimal solutions from the optimisation runs. Vulnerabilities with lower average values have been prioritised for mitigation more frequently, indicating higher mitigation importance.")

            v_columns = df.columns[1:-3]
            v_data = df[v_columns].apply(pd.to_numeric, errors='coerce')
            v_means = v_data.mean()
            st.bar_chart(v_means)

            st.info("You can visualise the mitigation effectiveness of the most Pareto-optimal trial from each optimisation run by selecting a Trial ID below. Higher parameter values indicate greater effectiveness of mitigation strategies against the corresponding vulnerabilities.")

            trial_ids = df.iloc[:, -4].dropna().astype(str).tolist()
            selected_trial_id = st.selectbox("Select a Trial ID", trial_ids)

            if selected_trial_id:
                filename = f"{selected_trial_id}.txt"
                if os.path.exists(filename):
                    with open(filename, "r") as file:
                        lines = file.readlines()
                        for line in lines:
                            if line.strip().startswith("Params:"):
                                params_str = line.strip().split("Params:")[1].strip()
                                params = ast.literal_eval(params_str)
                                df_trials = pd.DataFrame([params], index=[selected_trial_id])
                                st.bar_chart(df_trials.T)
                                break
                else:
                    st.warning(f"File {filename} does not exist.")
            else:
                st.info("Select a trial ID to view its parameter values.")
