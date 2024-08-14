import pandas as pd
import json
import re

if __name__ == "__main__":
    path = "./config/build_sources/mappings"

    # load spreadsheet tables
    mapping_spreadsheet = pd.read_excel(
        f"{path}/mappings.xlsx",
        sheet_name="Blue Team Guide"
    )

    ism_spreadsheet = pd.read_excel(
        f"{path}/mappings.xlsx",
        sheet_name="ISM Controls"
    )

    nist_spreadsheet = pd.read_excel(
        f"{path}/mappings.xlsx",
        sheet_name="NIST Controls"
    )
    
    mitre_spreadsheet = pd.read_excel(
        f"{path}/mappings.xlsx",
        sheet_name="MITRE Controls"
    )

    # globals
    mapping_data = json.loads(mapping_spreadsheet.to_json())
    ism_data = json.loads(ism_spreadsheet.to_json())
    nist_data = json.loads(nist_spreadsheet.to_json())
    mitre_data = json.loads(mitre_spreadsheet.to_json())

    columns = []
    table = {}
    output = {}
    
    ism_list = {}
    nist_list = {}
    mitre_list = {}

    # create ism mappings dictionary
    for column in ism_data:
        for index, row in enumerate(ism_data[column].values()):
            description = ism_data["Description"][str(index)]
            control = ism_data["Identifier"][str(index)]
            section = ism_data["Section"][str(index)]

            ism_list[control] = {}
            ism_list[control]["description"] = description
            ism_list[control]["section"] = section
            ism_list[control]["code"] = control
            ism_list[control]["url"] = f"https://ismcontrol.xyz/{control.split('-')[1]}"

    # create nist mapping dictionary
    for column in nist_data:
        for index, row in enumerate(nist_data[column].values()):
            control = nist_data["Control Identifier"][str(index)]
            description = nist_data["Control (or Control Enhancement)"][str(index)]
            section = nist_data["Control (or Control Enhancement) Name"][str(index)]

            # the nist control doesn't have a 0 prefix
            if len(re.findall(r"[A-Z]{2}-[0-9]{1,2}", control)[0].split("-")[1]) == 1:
                control = f"{control[:3]}0{control[3:]}"

            nist_list[control] = {}
            nist_list[control]["code"] = control
            nist_list[control]["description"] = description
            nist_list[control]["section"] = section
            nist_list[control]["url"] = f"https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element={control}"

    # create mitre mapping dictionary
    for column in mitre_data:
        for index, row in enumerate(mitre_data[column].values()):
            control = mitre_data["ID"][str(index)]
            description = mitre_data["Description"][str(index)]
            section = mitre_data["Name"][str(index)]

            mitre_list[control] = {}
            mitre_list[control]["code"] = control
            mitre_list[control]["description"] = description
            mitre_list[control]["section"] = section
            mitre_list[control]["url"] = f"https://attack.mitre.org/mitigations/{control}"

    # for each column in spreadsheet
    for ch in mapping_data.keys():
        column_header = ch.lower()
        columns.append(column_header)

        # create skeleton dictionary
        table[column_header] = []
        
        # keep track of over-arching technique
        overarching_technique = None

        # for each row in the column
        for row in mapping_data[ch].values():

            # technique
            if column_header == "technique":
                value = re.findall(r".*?\s\(((TA?|\.)[0-9]{3,4})\)", str(row))[0][0]
                
                # determine if the value is a tactic/technique
                # if so, make it over-arching and tack on .xxx
                if re.match(r"TA?[0-9]{4}", value):
                    overarching_technique = value
                else:
                    value = f"{overarching_technique}{value}"

                table[column_header].append(value)

            # module
            if column_header == "module":
                value = re.findall(r"•\s(.*)", str(row))
                table[column_header].append(value)

            # evidence
            if column_header == "evidence":
                lists = str(row).split("WINDOWS")

                if len(lists) >= 2:
                    windows = re.findall(r"(.*)\:\s(.*)", lists[0])
                    linux = re.findall(r"(.*)\:\s(.*)", lists[1])

                    table[column_header].append({
                        "linux": linux,
                        "windows": windows
                    })
                else:
                    table[column_header].append({
                        "linux": [],
                        "windows": []
                    })

            # tools
            if column_header == "tools":
                value = str(row).split()
                table[column_header].append(value)

            # mitigation
            if column_header == "mitigation":
                value = re.findall(r"\.*?\((M[0-9]{4})\)", str(row))
                table[column_header].append(value)

            # ism
            if column_header == "ism":
                value = re.findall(r"ISM-([0-9]{4})", str(row))
                table[column_header].append(value)
        
            # nist
            if column_header == "nist":
                value = re.findall(r".*?\s\(([A-Z]{1,2}-[0-9]{1,2})\)", str(row))
                table[column_header].append(value)

    # format json data into a better dictionary
    for index, technique in enumerate(table["technique"]):

        # don't add tactics
        if not re.match(r"TA[0-9]{4}", technique):
            # create a new dictionary for each technique
            output[technique] = {}
            
            for column in columns:
                if not column == "artefacts":
                    output[technique][column] = []

                    if column == "ism":
                        ism_controls = table[column][index]
                        
                        for ism_control in ism_controls:
                            ism_control = f"ISM-{ism_control}"

                            output[technique][column].append(ism_list[ism_control])
                    elif column == "nist":
                        nist_controls = table[column][index]

                        for nist_control in nist_controls:
                            output[technique][column].append(nist_list[nist_control])
                    elif column == "mitigation":
                        mitre_controls = table[column][index]

                        for mitre_control in mitre_controls:
                            output[technique][column].append(mitre_list[mitre_control])
                    else:
                        output[technique][column] = table[column][index]
    
    # serialise output json
    json_object = json.dumps(output, indent=4)
    
    # write to file
    with open(f"{path}/mappings.json", "w") as outfile:
        outfile.write(json_object)