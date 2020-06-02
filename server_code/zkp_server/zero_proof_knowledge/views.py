from django.shortcuts import render

# Create your views here.

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from . import group_utilities
import json
import ssl

@csrf_exempt
def validate_zero_proof_knowledge(request):
    if request.method == 'POST':
        zkp_manager = group_utilities.ZkpManager()
        verifier = zkp_manager.new_verifier()

        data = json.loads(request.body)
        """
        Expected data format:
        {
            "y" : int,
            "a" : int,
            "z" : int,
            "UserID" : string,
            "OtherInfo" : string
        }
        """
        y = data["y"]
        a = data["a"]
        z = data["z"]

        # Creation of the string needed to compute the challange c as H(g||a||y||user_id||other_info)
        g_str = str(zkp_manager.get_g())
        a_str = str(a)
        y_str = str(y)
        user_id = data["user_id"]
        other_info = ssl.get_server_certificate(("www.theamazinggroup14.it", 443))
        to_hash_string = g_str + a_str + y_str + user_id + other_info

        verifier.compute_challenge(to_hash_string)

        verified = verifier.verify(y, a, z)
        if verified:
            return HttpResponse("Zero knowledge proof successfully verified.")
        else:
            return HttpResponse("Zero knowledge proof failed.")
    return HttpResponse("You should POST your zkp parameters.")
