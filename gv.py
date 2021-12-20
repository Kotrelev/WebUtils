from diagrams import Diagram, Edge
from diagrams.custom import Custom
from diagrams.ibm.network import Bridge
from diagrams.ibm.network import Router
from diagrams.ibm.network import InternetServices
from diagrams.ibm.network import DirectLink
from diagrams.generic.blank import Blank
from diagrams.aws.compute import EC2
from diagrams.aws.database import RDS
from diagrams.aws.network import ELB

with Diagram("Web Service", show=False, filename="/home/kotrelev/graph"):
    ELB("lb") >> EC2("web") >> RDS("userdb")

