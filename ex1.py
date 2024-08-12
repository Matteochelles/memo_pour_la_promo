# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright 2024 Marta Rybczynska

import json
import os
import re
import argparse
from cvev5 import get_status, parse_cve_id

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CVE lookup in CVEV5 database for a given product"
    )
    parser.add_argument("-i", "--input-dir", help="Input directory", required=True)
    args = parser.parse_args()

    input_dir = args.input_dir

    max_for_year = {}
    ids_for_year = {}

    print("Loading database...")
    for root, dirnames, filenames in os.walk(input_dir):
        for filename in filenames:
            year, number = parse_cve_id(filename)
            if year is not None:
                # Special case: we haven't see that year before
                if year not in ids_for_year:
                    max_for_year[year] = int(number)
                    ids_for_year[year] = []
                else:
                    # Check if we have the max for that year
                    if max_for_year[year] < int(number):
                        max_for_year[year] = int(number)
                ids_for_year[year].append(int(number))

    print("Maximum values for each year")
    print(max_for_year)

    print("Dumping data for each year:")
    for year in max_for_year:
        print ("Year:", year)
        ids_for_year[year].sort()

        # Initializations: we're not in a gap, start from 1
        in_gap = False
        i = 1
        gap_start = 1
        max_this_year = max_for_year[year]
        while i < max_this_year:
            # If this is a beginning of a gap (an id that is not on the list)
            if i not in ids_for_year[year] and in_gap == False:
                gap_start = i
                in_gap = True
            # If this is the end of the gap (on the list, but in_gap is True)
            elif i in ids_for_year[year] and in_gap == True:
                in_gap = False
                print("Year: %s gap %s (included) to %s (excluded)" % (year, gap_start, i-1))
            # All cases
            i += 1
