"""Issue/revoke MCP credentials. MCP can never attest owner confirmation."""
import argparse
from aifilter import config
from aifilter.mcp_server import issue_token, revoke_token
from aifilter.store import Store

def main():
    p=argparse.ArgumentParser(); s=p.add_subparsers(dest="cmd",required=True)
    i=s.add_parser("issue"); i.add_argument("client"); i.add_argument("--scope",choices=("read","tighten"),required=True)
    r=s.add_parser("revoke"); r.add_argument("client")
    a=p.parse_args(); st=Store(config.db_path())
    if a.cmd=="issue": print(issue_token(st,a.client,a.scope))
    elif a.cmd=="revoke": revoke_token(st,a.client); print("revoked")
if __name__=="__main__": main()
