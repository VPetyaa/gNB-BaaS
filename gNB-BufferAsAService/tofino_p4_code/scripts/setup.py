p4dev = "BFD"
print(p4dev)
p4 = bfrt.hiran

# This function can clear all the tables and later on other fixed objects
# once bfrt support is added.
def clear_all():
    global p4

    # The order is important. We do want to clear from the top, i.e.
    # delete objects that use other objects, e.g. table entries use
    # selector groups and selector groups use action profile members
    
    # Clear Match Tables
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR']: 
            print("Clearing table {}".format(table['full_name']))
            for entry in table['node'].get(regex=True):
                entry.remove()
    # Clear Selectors
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['SELECTOR']:
            print("Clearing ActionSelector {}".format(table['full_name']))
            for entry in table['node'].get(regex=True):
                entry.remove()
    # Clear Action Profiles
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['ACTION_PROFILE']:
            print("Clearing ActionProfile {}".format(table['full_name']))
            for entry in table['node'].get(regex=True):
                entry.remove()
    
clear_all()

forward = p4.Ingress.buffering

if p4dev == "BFD":
# BFD
    forward.add_with_set_eport(port=0, ingress_port=4)
    forward.add_with_set_eport(port=4,  ingress_port=0)

else:
# BFS
    forward.add_with_set_eport(port=0,  ingress_port=4)
    forward.add_with_set_eport(port=4, ingress_port=0)

# Final programming
print("""
******************* PROGAMMING RESULTS *****************
""")
print ("Table forward:")
forward.dump(table=True)
