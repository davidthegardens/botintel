import pandas as pd
import requests
from keymanager import KeyManager as km
from Genealogy import Gene

forta_api = "https://api.forta.network/graphql"
headers = {"content-type": "application/json"}
headers['Authorization']=km().Easy_Key('forta_api_key')
# start and end date needs to be in the format: YYYY-MM-DD
startDate = "2023-07-10"
endDate = "2023-07-20"

def queryBot(bot,startDate,endDate,firstEntries):

  query = """
    query exampleQuery($input: AlertsInput) {
      alerts(input: $input) {
        alerts {
          name
          protocol
          findingType
          source {
            transactionHash
            block {
              number
              chainId
              timestamp
              hash
            }
            bot {
              id
            }
          }
          severity
          metadata
          alertId
          addresses
          description
          hash
        }
        pageInfo {
          hasNextPage
          endCursor {
            blockNumber
            alertId
          }
        }
      }
    }
    """

  query_variables = {
    "input": {
      "first": firstEntries,
      "bots":[bot],
      "blockDateRange": {
        "startDate": startDate,
        "endDate": endDate
      }
    }
  }

  payload = dict(query=query, variables=query_variables)

  response = requests.post(forta_api, json=payload, headers=headers).json()

  return response

def get_token_names(shortresponse):
  token_types=shortresponse['metadata']['tokenTypes']
  token_types=token_types.split(",")
  return token_types

def get_addresses(shortresponse):
  return shortresponse['addresses']

def get_addresses_families(shortresponse):
  txhash=shortresponse['source']['transactionHash']
  addresses=get_addresses(shortresponse)
  ##### ADD CHECK: if not in graph:
  for address in addresses:
    Gene().masterSleuth(address,"anom_tx"+"".join(list(txhash)[2:6])+"_addr"+"".join(list(address)[2:6]),100,False)
    print(address)

resp=queryBot("0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8",startDate,endDate,firstEntries=5)

for i in resp['data']['alerts']['alerts']:
  get_addresses_families(i)
#get_addresses_families(resp)
