<img src="logo.png" alt="BAYMODS" width="140" height="140" style="display: block; margin: 0 auto 20px;">

# BAYMODS (Bayesian and Multi-Objective Decision Support)

## Overview

BAYMODS (Bayesian and Multi-Objective Decision Support) is an interactive web-based tool for Cyber-Physical System (CPS) decision support using Bayesian Networks and multi-objective optimization. This application provides a user-friendly interface for analyzing vulnerabilities in CPS environments through probabilistic modeling and supporting decision-making with multi-objective optimization.

## Features

- **Bayesian Network Model Analysis**: Upload and analyze CPS attack models in AutomationML format
- **Risk Assessment**: Calculate and analyze security risks using Bayesian inference techniques
- **Multi-Objective Optimization**: Find optimal defense strategies balancing system availability and risk reduction
- **Example Models**: Pre-configured attack scenarios including automotive, energy grid, and solar power systems

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Required Dependencies

Install the required Python packages:

The project includes a `requirements.txt` file with all necessary dependencies. Install using:

```bash
pip install -r requirements.txt
```
## Usage

### Running the Application

1. Clone the repository:

```bash
git clone https://github.com/shaofeihuang/BAYMODS.git
cd BAYMODS
```

2. Launch the Streamlit application:

```bash
streamlit run main.py
```

3. Open your web browser and navigate to the local URL provided (typically `http://localhost:8501`)

### Using the Application

1. **Upload Attack Model**: Upload an AutomationML file from the sidebar
   - Sample models are available in the `examples/` directory
   - Supports various CPS attack scenarios

2. **Run Optimization Trials**:
   - Execute single or multiple optimization runs with preset number of trials in each optimization run 

3. **Analyze Results**:
   - Review and explore optimized defense strategies

## Project Structure

```
BAYMODS/
├── .gitignore        # Git ignore file
├── LICENSE           # MIT License
├── main.py           # Main Streamlit application
├── utils.py          # Utility functions for Bayesian Network operations
├── logo.png          # Application logo
├── requirements.txt  # Python package dependencies (optional)
├── examples/         # Example attack model files
    ├── BlackEnergy.aml
    ├── Frosty-Goop.aml
    ├── Generic_CPS.aml
    ├── Railway-CBTC.aml
    ├── Smart-Healthcare.aml
    ├── Solar-PV-Inverter.aml
    ├── Stuxnet.aml
    └── Tesla-IVI.aml

## File Format

BAYMODS uses AutomationML files for model specification. These files define:

- Attack graph nodes and relationships
- Conditional probability distributions
- Defense mechanisms and their parameters
- Cost and effectiveness metrics

## Examples

The `examples/` directory contains eight pre-configured attack scenarios:
- **BlackEnergy.aml**: Models the BlackEnergy malware attack scenario
- **Generic_CPS.aml**: Generic cyber-physical system attack model
- **Solar-PV-Inverter.aml**: Solar photovoltaic inverter system security assessment
- **Frosty-Goop.aml**: Models the Frosty Goop attack on Ukrainian energy infrastructure
- **Railway-CBTC.aml**: Railway Communications-Based Train Control (CBTC) system attack model
- **Smart-Healthcare.aml**: Smart healthcare system security assessment
- **Stuxnet.aml**: Models the Stuxnet malware attack scenario
- **Tesla-IVI.aml**: Tesla In-Vehicle Infotainment (IVI) system attack model
## Author & Contact

**Author**: Shaofei Huang

**GitHub**: [@shaofeihuang](https://github.com/shaofeihuang)

**Repository**: [BAYMODS](https://github.com/shaofeihuang/BAYMODS)

For questions, issues, or contributions, please open an issue on the GitHub repository.

## License

Please refer to the repository for license information.

## Acknowledgments

This tool leverages:
- [Streamlit](https://streamlit.io/) for the web interface
- [pgmpy](https://pgmpy.org/) for Bayesian Network modeling
- [Optuna](https://optuna.org/) for multi-objective optimization

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs, feature requests, or improvements.
