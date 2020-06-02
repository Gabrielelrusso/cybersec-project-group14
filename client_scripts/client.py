import requests
import json
import secrets
import group_utilities
import ssl

"""
Setup
"""
zkp_manager = group_utilities.ZkpManager()


"""
You can use the provided test values in order to play with the zero knowledge proof protocol.
"""
y_test = zkp_manager.get_y_test()
x_test = zkp_manager.get_x_test()


# If "simulated" is True the secret used for the zkp is randomly generated,
# otherwise (if valid) the param "secret" is used; if the secret is not valid it will be random generated anyway.
prover = zkp_manager.new_prover(simulated=True, secret=None)


"""
Computation of the values used in the zero knowledge proof.
"""
node_id = secrets.token_hex(32)

y = prover.get_y()
a = prover.get_a()

# Creation of the string needed to compute the challange c: H(g||a||y||user_id||other_info)
g_str = str(zkp_manager.get_g())
a_str = str(a)
y_str = str(y)
user_id = node_id
print("Asking the server for its SSL certificate...")
other_info = ssl.get_server_certificate(("www.theamazinggroup14.it", 443))
print("SSL certificate successfully retrieved!")
to_hash_string = g_str + a_str + y_str + user_id + other_info

print("Computing non-interactive zero knowledge proof parameters...")
prover.compute_parameters(to_hash_string=to_hash_string)

z = prover.get_z()

"""
Send payload as a HTTP POST request on the server
"""
payload = {
    "y": y,
    "a": a,
    "z": z,
    "user_id": user_id
}

print("Sending parameters to the server...")
response = requests.post("https://www.theamazinggroup14.it/zero_proof_knowledge/", data=json.dumps(payload), verify = '/etc/ssl/certs/cacert.pem')
print("Server response: "+response.text)
