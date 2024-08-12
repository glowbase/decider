import pandas as pd
import json
import re

if __name__ == "__main__":
    path = "./config/build_sources/mappings"

    # load spreadsheets
    mapping_spreadsheet = pd.read_excel(
        f"{path}/mappings.xlsx",
        sheet_name="Blue Team Guide"
    )

    ism_spreadsheet = pd.read_excel(
        f"{path}/mappings.xlsx",
        sheet_name="ISM Controls (June 2024)"
    )

    # globals
    mapping_data = json.loads(mapping_spreadsheet.to_json())
    ism_data = json.loads(ism_spreadsheet.to_json())

    columns = []
    table = {}
    output = {}
    controls = {}

    # create ism mappings dictionary
    for column in ism_data:
        for index, row in enumerate(ism_data[column].values()):
            description = ism_data["Description"][str(index)]
            control = ism_data["Identifier"][str(index)]
            section = ism_data["Section"][str(index)]

            controls[control] = {}
            controls[control]["description"] = description
            controls[control]["section"] = section
            controls[control]["code"] = control

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

            # remediation
            if column_header == "remediation":
                value = re.findall(r"\.*?\((M[0-9]{4})\)", str(row))
                table[column_header].append(value)

            # ism
            if column_header == "ism":
                value = re.findall(r".*?ISM - ([0-9]{4})", str(row))
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

                            output[technique][column].append(controls[ism_control])
                    else:
                        output[technique][column] = table[column][index]
    
    # serialise output json
    json_object = json.dumps(output, indent=4)
    
    # write to file
    with open(f"{path}/mappings.json", "w") as outfile:
        outfile.write(json_object)