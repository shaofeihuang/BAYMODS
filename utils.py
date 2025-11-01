import streamlit as st
import numpy as np
import xml.etree.ElementTree as ET
import networkx as nx
import matplotlib.pyplot as plt
import itertools
import re, os, csv, json
import math
import optuna
from datetime import date, datetime
from dataclasses import dataclass, field
from collections import defaultdict
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination
from concurrent.futures import ProcessPoolExecutor

@dataclass
class Environment:
    element_tree_root: object
    t: object

@dataclass
class AMLData:
    probability_data: object
    AssetinSystem: object
    HazardinSystem: object
    VulnerabilityinSystem: object
    max_num_parents: int
    total_elements: int
    connections: object
    connections_mapped: object
    result_list: object

@dataclass
class NodeContext:
    num_parents: object
    matching_hazard_nodes: list = field(default_factory=list)
    matching_vulnerability_nodes: list = field(default_factory=list)
    matching_asset_nodes: list = field(default_factory=list)

def setup_environment(aml_content):
    ET_root = ET.fromstring(aml_content)
#    time_difference = date.today() - st.session_state['date_input']
    time_difference = date.today() - datetime.strptime(st.session_state['date_input'], "%Y-%m-%d").date()
    days = time_difference.days
    hours = divmod(time_difference.seconds, 3600)[0]
    t = days * 4 + (24 - hours)
    return ET_root, t

def get_attribute_value(internal_element, attribute_name):
    ValueTag=".//{http://www.dke.de/CAEX}Value"
    attribute_tag = internal_element.find(f".//{{http://www.dke.de/CAEX}}Attribute[@Name='{attribute_name}']")
    if attribute_tag is not None:
        value_element = attribute_tag.find(ValueTag)
        if value_element is not None:
            return float(value_element.text)
    return None

def calculate_probability_of_failure(failure_rate_value, t):
    failure_rate = float(failure_rate_value)
    return 1 - math.exp(-(failure_rate * t))

def calculate_probability_of_human_error(human_error_percentage_value, t):
    human_error_in_percent = float(human_error_percentage_value)
    human_error_rate = human_error_in_percent / (100 * 8760)
    return 1 - math.exp(-(human_error_rate * t))

def check_probability_data(aml_data: AMLData):
    for data in aml_data.probability_data:
        print("ID:", data['ID'], "Name:", data['Name'], "RefSystemUnitPath:", data['RefBaseSystemUnitPath'],
            "Prob of Failure:", data['Probability of Failure'], "Prob of Exposure:", data['Probability of Exposure'],
            "Prob of Impact:", data['Probability of Impact'], "Prob of Mitigation:", data['Probability of Mitigation'],
            "Prob of Human Error:", data['Probability of Human Error'])

def clean_aml_content(aml_content):
    aml_content = aml_content.strip()
    if aml_content.startswith("```xml"):
        aml_content = aml_content[len("```xml"):].strip()
    if aml_content.endswith("```"):
        aml_content = aml_content[:-len("```")].strip()
    return aml_content

def load_model_attributes():
    aml_content = clean_aml_content(st.session_state['aml_file'])
    env = Environment(*setup_environment(aml_content))
    aml_data = AMLData(*process_AML_file(env.element_tree_root, env.t))
    st.session_state['aml_data'] = aml_data
    st.session_state['env'] = env
    st.session_state['aml_attributes'] = {
        'assets': aml_data.AssetinSystem,
        'vulnerabilities': aml_data.VulnerabilityinSystem,
        'hazards': aml_data.HazardinSystem
    }

def process_AML_file(root, t):
    max_num_parents = 0
    allinone_attrib = []
    allinone_tags = []
    allinone_text = []
    name_id_tag_list = []
    name_list = []
    id_list = []
    tag_list = []
    RefPartnerBegin_list = []
    RefPartnerTerminate_list = []
    InternalLinks = []
    interface_to_element_map = {}
    external_interfaces_list = []
    probability_data = []
    AssetinSystem = []
    HazardinSystem = []
    VulnerabilityinSystem = []
    connections = []
    connections_mapped = []
    result_list = []
    total_elements = set()
    
    ns = {'caex': 'http://www.dke.de/CAEX'}

    for k in root.findall('.//'):
        allinone_attrib.append(k.attrib)
        allinone_tags.append(k.tag)
        allinone_text.append(k.text)

    for i, component_attrib in enumerate(allinone_attrib):
        name = component_attrib.get('Name')
        ID = component_attrib.get('ID')
        RPA = component_attrib.get('RefPartnerSideA')
        RPB = component_attrib.get('RefPartnerSideB')
        if name:
            name_list.append(name)
        if ID:
            id_list.append(ID)
        if name and ID:
            tag = allinone_tags[i]
            tag_list.append(tag)
            name_id_tag_list.append({'Name': name, 'ID': ID, 'Tag': tag})
        if RPA:
            RefPartnerBegin_list.append(RPA)
        if RPB:
            RefPartnerTerminate_list.append(RPB)
        if RPA and RPB:
            InternalLinks.append({RPA, RPB})

    if len(InternalLinks) == 0:
        for internal_link in root.findall('.//caex:InternalLink', ns):
            rpa = internal_link.find('caex:RefPartnerSideA', ns)
            rpb = internal_link.find('caex:RefPartnerSideB', ns)
            if rpa is not None and rpb is not None:
                InternalLinks.append({rpa.text, rpb.text})

    internal_elements = root.findall(".//{http://www.dke.de/CAEX}InternalElement")

    for internal_element in internal_elements:
        internal_element_id = internal_element.get('ID')
        internal_element_name = internal_element.get('Name')
        internal_element_impact_rating = internal_element.get('Impact Rating')
        ref_base_system_unit_path = internal_element.get('RefBaseSystemUnitPath')

        failure_rate_value = get_attribute_value(internal_element, 'FailureRatePerHour')
        probability_of_failure = (
            calculate_probability_of_failure(failure_rate_value, t) 
            if failure_rate_value is not None 
            else 0
        )

        probability_of_exposure_value = get_attribute_value(internal_element, 'Probability of Exposure')
        probability_of_exposure = probability_of_exposure_value if probability_of_exposure_value is not None else 0

        probability_of_impact_value = get_attribute_value(internal_element, 'Probability of Impact')
        probability_of_impact_vulnerability = probability_of_impact_value if probability_of_impact_value is not None else 0

        probability_of_mitigation_value = get_attribute_value(internal_element, 'Probability of Mitigation')
        probability_of_mitigation = probability_of_mitigation_value if probability_of_mitigation_value is not None else 0

        human_error_percentage_value = get_attribute_value(internal_element, 'HumanErrorEstimationPercentage')
        probability_of_human_error = (
            calculate_probability_of_human_error(human_error_percentage_value, t) 
            if human_error_percentage_value is not None 
            else 0
        )

        if internal_element_impact_rating is None:
            internal_element_data = {
                'ID': internal_element_id,
                'Name': internal_element_name,
                'Probability of Failure': probability_of_failure,
                'Probability of Exposure': probability_of_exposure,
                'Probability of Impact' : probability_of_impact_vulnerability,
                'Probability of Mitigation' : probability_of_mitigation,
                'Probability of Human Error': probability_of_human_error,
                'RefBaseSystemUnitPath': ref_base_system_unit_path
            }
        else:
            internal_element_data = {
                'ID': internal_element_id,
                'Name': internal_element_name,
                'Impact Rating': internal_element_impact_rating,
                'Probability of Failure': probability_of_failure,
                'Probability of Exposure': probability_of_exposure,
                'Probability of Impact' : probability_of_impact_vulnerability,
                'Probability of Mitigation' : probability_of_mitigation,
                'Probability of Human Error': probability_of_human_error,
                'RefBaseSystemUnitPath': ref_base_system_unit_path
            }

        if ref_base_system_unit_path.startswith ('AssetOfICS/'):
            AssetinSystem.append(internal_element_data)
        elif ref_base_system_unit_path == 'HazardforSystem/Hazard':
            HazardinSystem.append(internal_element_data)
        elif ref_base_system_unit_path == 'VulnerabilityforSystem/Vulnerability':
            VulnerabilityinSystem.append(internal_element_data)

        probability_data.append(internal_element_data)

    for internal_element in root.findall(".//{http://www.dke.de/CAEX}InternalElement"):
        external_interfaces = internal_element.findall(".//{http://www.dke.de/CAEX}ExternalInterface")
        if len(external_interfaces) < 5:
            internal_element_id = internal_element.get('ID')
            internal_element_name = internal_element.get('Name')
            for external_interface in external_interfaces:
                external_interface_id = external_interface.get('ID')
                external_interface_name = external_interface.get('Name')
                external_interface_ref_base_class_path = external_interface.get('RefBaseClassPath')
                external_interface_info = {
                    'InternalElement ID': internal_element_id,
                    'InternalElement Name': internal_element_name,
                    'ExternalInterface ID': external_interface_id,
                    'ExternalInterface Name': external_interface_name,
                    'ExternalInterface RefBaseClassPath': external_interface_ref_base_class_path
                    }
                external_interfaces_list.append(external_interface_info)

    for external_interface in external_interfaces_list:
        external_interface_id = external_interface['ExternalInterface ID']
        internal_element_id = external_interface['InternalElement ID']
        interface_to_element_map[external_interface_id] = internal_element_id

    for internal_link in root.findall(".//{http://www.dke.de/CAEX}InternalLink"):
        ref_partner_a = internal_link.get('RefPartnerSideA')
        ref_partner_b = internal_link.get('RefPartnerSideB')
        if ref_partner_a in interface_to_element_map and ref_partner_b in interface_to_element_map:
            internal_element_a = interface_to_element_map[ref_partner_a]
            internal_element_b = interface_to_element_map[ref_partner_b]
            connection = {'from': internal_element_a, 'to': internal_element_b}
            connections.append(connection)

    if len(connections) == 0:
        ns = {'caex': 'http://www.dke.de/CAEX'}
        for internal_link in root.findall('.//caex:InternalLink', ns):
            rpa = internal_link.find('caex:RefPartnerSideA', ns)
            rpb = internal_link.find('caex:RefPartnerSideB', ns)
            if rpa.text in interface_to_element_map and rpb.text in interface_to_element_map:
                internal_element_a = interface_to_element_map[rpa.text]
                internal_element_b = interface_to_element_map[rpb.text]
                connection = {'from': internal_element_a, 'to': internal_element_b}
                connections.append(connection)

    for connection in connections:
        from_interface = connection['from']
        to_interface = connection['to']
        if from_interface in interface_to_element_map:
            from_element = interface_to_element_map[from_interface]
        else:
            from_element = from_interface
        if to_interface in interface_to_element_map:
            to_element = interface_to_element_map[to_interface]
        else:
            to_element = to_interface
        mapped_connection = {'from': from_element, 'to': to_element}
        connections_mapped.append(mapped_connection)

    connections_from_to = defaultdict(list)
    connections_to_from = defaultdict(list)

    for connection in connections_mapped:
        from_element = connection['from']
        to_element = connection['to']
        total_elements.add(from_element)
        total_elements.add(to_element)
        connections_from_to[from_element].append(to_element)
        connections_to_from[to_element].append(from_element)

    number_of_children =  [{'Element': k, 'Number of children': len(v)} for k, v in connections_from_to.items()]
    number_of_parents =  [{'Element': k, 'Number of parents': len(v)} for k, v in connections_to_from.items()]

    for element in total_elements:
        child = next((c for c in number_of_children if c['Element'] == element), {'Number of children': 0})
        parent = next((p for p in number_of_parents if p['Element'] == element), {'Number of parents': 0})
        total_dependents = child['Number of children'] + parent['Number of parents']
        result_dict = {
            'Element': element,
            'Number of children': child['Number of children'],
            'Number of parents': parent['Number of parents'],
            'Total Dependents': total_dependents
        }

        for key in result_dict:
            if isinstance(result_dict[key], (int, float)):
                result_dict[key] /= len(total_elements)

        result_list.append(result_dict)
        parent = next((p for p in number_of_parents if p['Element'] == element), {'Number of parents': 0})
        num_parents = parent['Number of parents']

        if num_parents > max_num_parents:
            max_num_parents = num_parents

    return probability_data, AssetinSystem, HazardinSystem, VulnerabilityinSystem, max_num_parents, total_elements, connections, connections_mapped, result_list


def generate_cpd_values_hazard(num_parents):
    cpd_values = [[0] * (2 ** num_parents) for _ in range(2)]
    for i in range(2 ** num_parents):
        num_ones = bin(i).count('1')
        cpd_values[0][i] = (num_parents - num_ones) / num_parents
        cpd_values[1][i] = 1 - cpd_values[0][i]
    return cpd_values


def generate_cpd_values_exposure(node_context: NodeContext, NodeType: str):
    num_states = 2
    num_parents = node_context.num_parents
    cpd_values = np.zeros((num_states, 2 ** num_parents))
    num_parents = node_context.num_parents
    aml_data = st.session_state['aml_data']
    af_modifier = st.session_state['af_modifier_input']

    if NodeType == "Hazard":
        if num_parents == 0:
            cpd_values[:, 0] = 0.5
        elif num_parents == 1:
            cpd_values[0, 0] = 1
            cpd_values[0, 1] = 0
            cpd_values[1, :] = 1 - cpd_values[0, :]
        elif 2 <= num_parents <= aml_data.max_num_parents:
            cpd_values = generate_cpd_values_hazard(num_parents)

    elif NodeType == "Vulnerability":
        probability_of_exposure_for_node = node_context.matching_vulnerability_nodes[0]['Probability of Exposure']
        probability_of_mitigation_for_node = node_context.matching_vulnerability_nodes[0]['Probability of Mitigation']
        pofe = float(probability_of_exposure_for_node * (1 - probability_of_mitigation_for_node))
        #print("[DEBUG] ID:", node_context.matching_vulnerability_nodes[0]['ID'], "Exposure:", probability_of_exposure_for_node, "Mitigation:", probability_of_mitigation_for_node, "POFE:", pofe)
        if num_parents == 0:
            cpd_values[0, 0] = pofe * af_modifier
            cpd_values[1, 0] = 1 - pofe * af_modifier
        elif num_parents >= 1:
            cpd_values[0, :-1] = pofe * af_modifier
            cpd_values[1, :-1] = 1 - pofe * af_modifier
            cpd_values[0, -1] = 0
            cpd_values[1, -1] = 1

    elif NodeType == "Asset":
        ref_base_for_node = node_context.matching_asset_nodes[0]['RefBaseSystemUnitPath']
        if ref_base_for_node.startswith ('AssetOfICS/'):
            probability_of_failure_for_node = node_context.matching_asset_nodes[0]['Probability of Failure']

###########################################################################################################
#   Scaling Algorithm
###########################################################################################################

            connections_from_to = defaultdict(list)

            for connection in aml_data.connections_mapped:
                from_element = connection['from']
                if node_context.matching_asset_nodes[0]['ID'] == from_element:
                    to_element = connection['to']
                    if re.match(r'^(V|\(V|\[V)\d', to_element):
                        connections_from_to[from_element].append(to_element)

            for asset, vulns in connections_from_to.items():
                num_vulns = len(vulns)

                sum_mitigation = 0.0  # Initialize sum for each asset

                for i in range(num_vulns):
                    matched = [element for element in aml_data.VulnerabilityinSystem if element['ID'] == vulns[i]]
                    if matched:
                        probability_of_mitigation = matched[0].get('Probability of Mitigation', 0.0)
                        if probability_of_mitigation > 0:
                            sum_mitigation += probability_of_mitigation
                    else:
                        print(f"No matching vulnerability found for ID {vulns[i]}")

                if num_vulns > 0:
                    scaling_factor = 1.0 / num_vulns
                    probability_of_failure_for_node = min(1.0, scaling_factor * sum_mitigation)
                    #print("Asset:", asset, "Probability of failure:", probability_of_failure_for_node)

###########################################################################################################

            if probability_of_failure_for_node:
                poff = float(probability_of_failure_for_node)
                cpd_values[0, :-1] = 1
                cpd_values[1, :-1] = 0
                cpd_values[0, -1] = poff
                cpd_values[1, -1] = 1 - poff
            else:
                cpd_values[0, :-1] = 1
                cpd_values[1, :-1] = 0
                cpd_values[0, -1] = 0
                cpd_values[1, -1] = 1
        elif ref_base_for_node == 'AssetOfICS/User':
            probability_of_human_error_for_node = node_context.matching_asset_nodes[0]['Probability of Human Error']
            pofhe = float(probability_of_human_error_for_node)
            cpd_values[0, 0] = pofhe
            cpd_values[1, 0] = 1 - pofhe
        else:
            probability_of_failure_for_node = node_context.matching_asset_nodes[0]['Probability of Failure']
            poff = float(probability_of_failure_for_node)
            cpd_values[0, 0] = poff
            cpd_values[1, 0] = 1 - poff

    cpd_values /= np.sum(cpd_values, axis=0)  # Normalize the CPD values
    return cpd_values.reshape((2, -1))


def generate_cpd_values_impact(node, node_context: NodeContext, NodeType: str):
    num_states = 2
    num_parents = node_context.num_parents
    aml_data = st.session_state['aml_data']
    cpd_values = np.zeros((num_states, 2 ** num_parents))
    current_entry = next((entry for entry in aml_data.result_list if entry['Element'] == node), None)

    if NodeType == "Hazard":
        if num_parents == 0:
            cpd_values[0, 0] = 0.5
            cpd_values[1, 0] = 0.5
        elif num_parents == 1:
            cpd_values[0, 0] = 1
            cpd_values[0, 1] = 0
            cpd_values[1, 0] = 1 - cpd_values[0, 0]
            cpd_values[1, 1] = 1 - cpd_values[0, 1]
        elif 2 <= num_parents <= aml_data.max_num_parents:
            cpd_values=generate_cpd_values_hazard(num_parents)

    elif NodeType == "Vulnerability":
        probability_of_impact_for_node = node_context.matching_vulnerability_nodes[0]['Probability of Impact'] * ( 1 - node_context.matching_vulnerability_nodes[0]['Probability of Mitigation'])
        pofi = float(probability_of_impact_for_node)
        if num_parents == 0:
            cpd_values[0, 0] = pofi
            cpd_values[1, 0] = 1 - pofi
        elif num_parents >= 1:
            cpd_values[0, :-1] = 1
            cpd_values[1, :-1] = 0
            cpd_values[0, -1] = pofi
            cpd_values[1, -1] = 1 - pofi

    elif NodeType == "Asset":
        ref_base_for_node = node_context.matching_asset_nodes[0]['RefBaseSystemUnitPath']
        if ref_base_for_node.startswith ('AssetOfICS/'):
            probability_of_failure_for_node = node_context.matching_asset_nodes[0]['Probability of Failure']
            if probability_of_failure_for_node:
                cpd_values[0, :-1] = 1
                cpd_values[1, :-1] = 0
                cpd_values[0, -1] = current_entry['Number of children']
                cpd_values[1, -1] = 1 - current_entry['Number of children']
            else:
                cpd_values[0, :-1] = 1
                cpd_values[1, :-1] = 0
                cpd_values[0, -1] = 0
                cpd_values[1, -1] = 1
        elif ref_base_for_node == 'AssetOfICS/User':
            cpd_values[0, 0] = current_entry['Number of children']
            cpd_values[1, 0] = 1 - current_entry['Number of children']
        else:
            cpd_values[0, 0] = current_entry['Number of children']
            cpd_values[1, 0] = 1 - current_entry['Number of children']

    cpd_values /= np.sum(cpd_values, axis=0)  # Normalize the CPD values
    return cpd_values.reshape((2, -1))


def shortest_path_length(graph, start_node, end_node):
    try:
        length = nx.shortest_path_length(graph, source=start_node, target=end_node)
        return length
    except nx.NetworkXNoPath:
        return float('inf')


def create_bbn_exposure():
    cpds = {}
    last_node = None
    aml_data = st.session_state['aml_data']

    bbn_exposure = DiscreteBayesianNetwork()
    connections = aml_data.connections_mapped
    bbn_exposure.add_nodes_from(aml_data.total_elements)
    bbn_exposure.add_edges_from([(connection['from'], connection['to']) for connection in connections])

    for node in bbn_exposure.nodes():
        node_context = NodeContext(
        num_parents = len(bbn_exposure.get_parents(node)),
        matching_hazard_nodes = [element for element in aml_data.HazardinSystem if element['ID'] == node],
        matching_vulnerability_nodes = [element for element in aml_data.VulnerabilityinSystem if element['ID'] == node],
        matching_asset_nodes = [element for element in aml_data.AssetinSystem if element['ID'] == node]
        )

        cpd_values = None

        if node_context.matching_hazard_nodes:
            cpd_values = generate_cpd_values_exposure(node_context, "Hazard")
        elif node_context.matching_vulnerability_nodes:
            cpd_values = generate_cpd_values_exposure(node_context, "Vulnerability")
        elif node_context.matching_asset_nodes:
            cpd_values = generate_cpd_values_exposure(node_context, "Asset")

        if cpd_values is None or np.any(np.isnan(cpd_values)):
            raise ValueError(f"Missing or invalid CPD values for node {node}")

        #print(f"[DEBUG] CPD values before normalization for node {node}: {cpd_values}")

        cpd = TabularCPD(variable=node, variable_card=2, values=cpd_values,
                        evidence=bbn_exposure.get_parents(node), evidence_card=[2] * node_context.num_parents)

        cpds[node] = cpd

    bbn_exposure.add_cpds(*cpds.values())

    last_nodes = [e['Element'] for e in aml_data.result_list if e['Number of children'] == 0]
    last_node = last_nodes[0] if last_nodes else None
#    print("\n[*] Last node in BBN:", last_node)

    return bbn_exposure, last_node


def create_bbn_impact(bbn_exposure):
    cpds = {}
    aml_data = st.session_state['aml_data']

    bbn_impact = DiscreteBayesianNetwork()
    bbn_impact.add_edges_from([(connection['from'], connection['to']) for connection in aml_data.connections])

    for node in bbn_impact.nodes():
        cpd_values = None

        node_context = NodeContext(
        num_parents = len(bbn_exposure.get_parents(node)),
        matching_hazard_nodes = [element for element in aml_data.HazardinSystem if element['ID'] == node],
        matching_vulnerability_nodes = [element for element in aml_data.VulnerabilityinSystem if element['ID'] == node],
        matching_asset_nodes = [element for element in aml_data.AssetinSystem if element['ID'] == node]
        )

        if node_context.matching_hazard_nodes:
            cpd_values = generate_cpd_values_impact(node, node_context, "Hazard")
        elif node_context.matching_vulnerability_nodes:
            cpd_values = generate_cpd_values_impact(node, node_context, "Vulnerability")
        elif node_context.matching_asset_nodes:
            cpd_values = generate_cpd_values_impact(node, node_context, "Asset")

        if cpd_values is None or np.any(np.isnan(cpd_values)):
            raise ValueError(f"Missing or invalid CPD values for node {node}")
        
        #print(f"[DEBUG] CPD values before normalization for node {node}: {cpd_values}")

        cpd = TabularCPD(variable=node, variable_card=2, values=cpd_values,
                        evidence=bbn_impact.get_parents(node), evidence_card=[2] * node_context.num_parents)
        
        cpds[node] = cpd

    bbn_impact.add_cpds(*cpds.values())

    return bbn_impact

def compute_risk_score():
    bbn_exposure, last_node = create_bbn_exposure()
    bbn_impact = create_bbn_impact(bbn_exposure)

    inference_exposure = VariableElimination(bbn_exposure)
    inference_impact = VariableElimination(bbn_impact)

    start_node = st.session_state['start_node']

    if 'attack_paths' in st.session_state:
        start_node = st.session_state['attack_paths'].split(" --> ")[0]

    cpd_prob, cpd_impact = compute_bayesian_probabilities(inference_exposure, inference_impact, st.session_state['aml_data'].total_elements, start_node, last_node)

    risk_score = cpd_prob * cpd_impact * 100

    st.session_state['cpd_prob'] = cpd_prob
    st.session_state['cpd_impact'] = cpd_impact
    st.session_state['risk_score'] = risk_score

    st.write("[*] Timestamp:", datetime.now())
    st.write("[*] Posterior Probability of Exposure:", cpd_prob)
    st.write("[*] Posterior Probability of Impact:", cpd_impact)
    st.write('[*] Risk score: {:.2f} %'.format(risk_score))
    display_metrics()


def check_bbn_models(bbn_exposure, bbn_impact):
    st.write("[*] Checking BBN (Exposure) structure consistency:", bbn_exposure.check_model())
    st.write("[*] Checking BBN (Impact) structure consistency:", bbn_impact.check_model())

def compute_bayesian_probabilities(inference_exposure, inference_impact, total_elements, source_node, target_node):
    for nodes in total_elements:
        if nodes == target_node:
            prob_failure = inference_exposure.query(variables=[nodes], evidence={source_node:1})
            prob_impact = inference_impact.query(variables=[nodes], evidence={source_node:1})
            cpd_prob = prob_failure.values
            cpd_impact = prob_impact.values
            return cpd_prob[0], cpd_impact[0]
        else:
            pass

def plot_bbn(bbn):
    graph = nx.DiGraph()
    graph.add_nodes_from(bbn.nodes())
    graph.add_edges_from(bbn.edges())
    pos = nx.kamada_kawai_layout(graph, scale=2)
    nx.draw_networkx_nodes(graph, pos, node_color='lightblue', node_size=300)
    nx.draw_networkx_edges(graph, pos, arrows=True, arrowstyle='->', arrowsize=10)
    nx.draw_networkx_labels(graph, pos)
    plt.title("Bayesian Belief Network")
    plt.axis('off')
    plt.show()

def display_metrics():
    st.sidebar.metric("Probability of Exposure", value=f"{st.session_state.get('cpd_prob', 0):.4f}")
    st.sidebar.metric("Probability of Severe Impact", value=f"{st.session_state.get('cpd_impact', 0):.4f}")
    st.sidebar.metric("Risk Score", value=f"{st.session_state.get('risk_score', 0):.2f}%")

def bbn_inference(node_context: NodeContext, source_node):
    cpds = {}
    cpd_values_list = []
    last_node = None
    aml_data = st.session_state['aml_data']
    num_parents = node_context.num_parents

    bbn_exposure = DiscreteBayesianNetwork()
    bbn_impact = DiscreteBayesianNetwork()
    aml_data.connections = aml_data.connections_mapped
    bbn_exposure.add_nodes_from(aml_data.total_elements)
    bbn_exposure.add_edges_from([(connection['from'], connection['to']) for connection in aml_data.connections])
    bbn_impact.add_edges_from([(connection['from'], connection['to']) for connection in aml_data.connections])

    for node in bbn_exposure.nodes():
        num_parents = len(bbn_exposure.get_parents(node))
        matching_hazard_nodes = [element for element in aml_data.HazardinSystem if element['ID'] == node]
        matching_vulnerability_nodes = [element for element in aml_data.VulnerabilityinSystem if element['ID'] == node]
        matching_asset_nodes = [element for element in aml_data.AssetinSystem if element['ID'] == node]

        cpd_values = None

        if matching_hazard_nodes:
            cpd_values = generate_cpd_values_exposure(node_context, "Hazard")
        elif matching_vulnerability_nodes:
            cpd_values = generate_cpd_values_exposure(node_context, "Vulnerability")
        elif matching_asset_nodes:
            cpd_values = generate_cpd_values_exposure(node_context, "Asset")

        cpd = TabularCPD(variable=node, variable_card=2, values=cpd_values,
                        evidence=bbn_exposure.get_parents(node), evidence_card=[2] * num_parents)

        cpds[node] = cpd
        cpd_values_list.append((node, cpd_values.tolist(), cpd.variables, cpd.cardinality))

    bbn_exposure.add_cpds(*cpds.values())

    last_node = None
    last_nodes = [e['Element'] for e in aml_data.result_list if e['Number of children'] == 0]
    last_node = last_nodes[0] if last_nodes else None

    for node in bbn_impact.nodes():
        num_parents = len(bbn_exposure.get_parents(node))
        cpd_values = None

        matching_hazard_nodes = [element for element in aml_data.HazardinSystem if element['ID'] == node]
        matching_vulnerability_nodes = [element for element in aml_data.VulnerabilityinSystem if element['ID'] == node]
        matching_asset_nodes = [element for element in aml_data.AssetinSystem if element['ID'] == node]

        if matching_hazard_nodes:
            cpd_values = generate_cpd_values_impact(node, num_parents, aml_data, node_context, "Hazard")
        elif matching_vulnerability_nodes:
            cpd_values = generate_cpd_values_impact(node, num_parents, aml_data, node_context, "Vulnerability")
        elif matching_asset_nodes:
            cpd_values = generate_cpd_values_impact(node, num_parents, aml_data, node_context, "Asset")

        cpd = TabularCPD(variable=node, variable_card=2, values=cpd_values,
                        evidence=bbn_exposure.get_parents(node), evidence_card=[2] * num_parents)

        cpds[node] = cpd
        cpd_values_list.append((node, cpd_values.tolist(), cpd.variables, cpd.cardinality))

    bbn_impact.add_cpds(*cpds.values())

    inference_exposure = VariableElimination(bbn_exposure)
    inference_impact = VariableElimination(bbn_impact)

    for nodes in aml_data.total_elements:
        if nodes == last_node:
            values = [f"{element['ID']}: {element['Probability of Mitigation']}" for element in aml_data.AssetinSystem if element['ID'] in [f"V{j}" for j in range(1,12)]]
            prob_exposure = inference_exposure.query(variables=[nodes], evidence={source_node:1})
            prob_failure = inference_impact.query(variables=[nodes], evidence={source_node:1})
            cpd_prob = prob_exposure.values
            cpd_impact = prob_failure.values
            st.write(", ".join(values), ",", cpd_prob[0], ",", cpd_impact[0], ", {:.2f}%".format(cpd_prob[0] * cpd_impact[0] * 100))
            return cpd_prob[0], 1 - cpd_impact[0], cpd_prob[0] * cpd_impact[0] * 100
        else:
            pass

def objective(trial, n_vulns):
    mitigation_prob_dict = {}

    for i in range(1, n_vulns + 1):
        prob_mitigation_value = trial.suggest_float(f'Mitigation_V{i}', 0, 1)
        mitigation_prob_dict[f'{i}'] = prob_mitigation_value

    for element in st.session_state['aml_data'].VulnerabilityinSystem:
        if element['ID'] in [f"V[{i}]" for i in range(1, n_vulns + 1)]:
            index = element['ID'][1:]  # Extract the numeric part of the ID (e.g., "V1" -> "1")
            element['Probability of Mitigation'] = mitigation_prob_dict[index]  # Replace with the corresponding value

    return bbn_inference()

def run_study(n_trials, n_vulns, graph, verbose, output):
    study = optuna.create_study(directions=["minimize", "minimize", "maximize"])
    study.optimize(lambda trial: objective(trial, n_vulns), n_trials, timeout=300)

    if graph:
        fig = optuna.visualization.plot_pareto_front(study, target_names=["Likelihood", "Impact", "Availability"])
        fig.show()

    trial_with_highest_availability = max(study.best_trials, key=lambda t: t.values[2])

    if verbose:
        st.write(f"Number of trials on the Pareto front: {len(study.best_trials)}")
        st.write("Trial with highest availability: ")
        st.write(f"\tTrial: {trial_with_highest_availability.number}")
        st.write(f"\tParams: {trial_with_highest_availability.params}")
        st.write(f"\tLikelihood: {trial_with_highest_availability.values[0]}, Impact: {trial_with_highest_availability.values[1]}, Availability: {trial_with_highest_availability.values[2]}")

    params = trial_with_highest_availability.params
    values = trial_with_highest_availability.values
    sorted_params = sorted(enumerate(params.values()), key=lambda item: item[1], reverse=True)
    sorted_indices = [item[0] for item in sorted_params]
    row = sorted_indices + [f"{values[0]:.3f}", f"{values[1]:.3f}", f"{values[2]:.3f}"]

    with open(output, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(row)