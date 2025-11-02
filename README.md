# BAYMODS

![BAYMODS Logo](logo.png)

## Overview

BAYMODS (Bayesian Modeling and Decision Support) is an interactive web-based tool for Cyber-Physical Systems (CPS) risk assessment using Bayesian Networks. This application provides a user-friendly interface for analyzing security risks in CPS environments through probabilistic modeling and multi-objective optimization.

## Features

- **Interactive Bayesian Network Visualization**: Upload and visualize CPS attack models in AML format
- **Risk Assessment**: Calculate and analyze security risks using Bayesian inference
- **Multi-Objective Optimization**: Find optimal defense strategies balancing cost and risk reduction
- **Real-time Analysis**: Dynamic probability updates and risk calculations
- **Example Models**: Pre-configured attack scenarios including BlackEnergy, Generic CPS, and Solar PV systems

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Required Dependencies

Install the required Python packages:

```bash
pip install streamlit
pip install pgmpy
pip install pandas
pip install networkx
pip install matplotlib
pip install numpy
pip install scipy
pip install pymoo
```

Or install all dependencies at once:

```bash
pip install streamlit pgmpy pandas networkx matplotlib numpy scipy pymoo
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

1. **Upload Attack Model**: Upload an AML (Attack Modeling Language) file from the sidebar
   - Sample models are available in the `examples/` directory
   - Supports BlackEnergy, Generic CPS, and Solar PV attack scenarios

2. **Configure Parameters**:
   - Set detection rates for different attack types
   - Define defense costs and effectiveness
   - Adjust risk thresholds

3. **Analyze Results**:
   - View Bayesian Network structure
   - Examine conditional probability tables
   - Review risk assessment metrics
   - Explore optimized defense strategies

## Project Structure

```
BAYMODS/
├── main.py           # Main Streamlit application
├── utils.py          # Utility functions for Bayesian Network operations
├── logo.png          # Application logo
├── examples/         # Example attack model files
│   ├── BlackEnergy.aml
│   ├── Generic_CPS.aml
│   └── SolarPV.aml
└── README.md         # This file
```

## File Format

BAYMODS uses AML (Attack Modeling Language) files for attack model specification. These files define:
- Attack graph nodes and relationships
- Conditional probability distributions
- Defense mechanisms and their parameters
- Cost and effectiveness metrics

## Examples

The `examples/` directory contains three pre-configured attack scenarios:

- **BlackEnergy.aml**: Models the BlackEnergy malware attack scenario
- **Generic_CPS.aml**: Generic cyber-physical system attack model
- **SolarPV.aml**: Solar photovoltaic system security assessment

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
- [pymoo](https://pymoo.org/) for multi-objective optimization

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs, feature requests, or improvements.
