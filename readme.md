# Threat Hunting Library

## Table of contents
- [Library Structure](#1-library-structure)
    - [Dependencies](#11-dependencies)
    - [Library Modules](#12-library-modules)
- [Functional Overview](#2-functional-overview)
    - [Threat Hunting Report](#21-threat-hunting-report)
    - [Cloud Interfaces](#22-interfaces)
        - [File Reputation](#file-reputation)
        - [File Similarity](#file-similarity)
        - [URI Statistics](#uri-statistics)
        - [Certificate Analytics](#certificate-analytics)
        - [Advanced Search](#advanced-search)
        - [Task Status](#task-status)
    - [Plugins](#23-plugins)


## 1. Library Structure
    .
    ├── dependencies            # Python wheel files for each dependency.
    ├── misc                    # Hunting metadata structure.
    ├── rl_threat_hunting       # Library modules.
    ├── tests                   # Test scripts with corresponding test data.
    ├── utils                   # Stand-alone helper scripts.
    └── README.md
    
### 1.1 Dependencies
All dependencies that are necessary for this library are stored in the
`dependencies` folder, divided by their usage. 

    .
    ├── dependencies            # Python wheel files for each dependency.
    |   ├── build               # Build-time dependancies.
    |   └── run                 # Run-time dependancies.
    └── ...
    
Particularly useful are run-time dependencies since some integrations like
Phantom require specific wheel files for applications that are installed on the
Phantom platform. 
Check the `wheels` folder for following projects:
[Phantom A100](https://github.rl.lan/product-integrations/phantom-a1000/tree/tc_threat_hunting/wheels),
[Phantom TiScale](https://github.rl.lan/product-integrations/phantom-tiscale).

### 1.2 Library modules
The core modules of this library are located in the `rl_threat_hunting` folder.
A brief descriptions of each module and submodule are given in the directory
tree below.

    .
    ├── rl_threat_hunting              # Library modules.
    |   ├── adapter                    # Modules for generating hunting report and its sections.
    |   ├── atlas                      # Family and ATT&CK matrix descriptions.
    |   ├── cloud                      # TiCloud interface.
    |   ├── filter                     # Metadata filters for Advanced Search queries.
    |   ├── local                      # A1000 Advanced Search interface (only local A1000 data).
    |   ├── plugins                    # Threat hunting modules for other analysis tools (e.g. JoeSandbox, RL Cloud Dynamic Analysis).
    |   ├── __init__.py
    |   ├── child_evaluation.py        # Logic for selecting most interesting extracted files (children).
    |   ├── constants.py
    |   ├── file_report.py             # File handling functions (functions ensure proper character coding and decoding).
    |   ├── local_reputation.py        # A1000 local file reputation hunting logic.
    |   ├── mwp_metadata_adapter.py    # Hunting MWP metadata parser and composer.
    |   ├── result_evaluation.py       # Classification logic.
    |   ├── tc_metadata_adapter.py     # Top-level hunting metadata composer.
    |   └── utils.py
    └── ...

## 2. Functional Overview 
In a nutshell, this library is used to process TiCore metadata and responses from selected
TiCloud APIs.
The library is going to extract interesting segments and translate them into more 
readable form called threat hunting report.
Definition of the threat hunting report is placed in the `misc/metadata_format.def`
and it should maintained properly.

### 2.1 Threat Hunting Report
Threat hunting report represents a state of some hunting workflow.
From a report creation, until the workflow end, the report is going to be constantly
expanded and updated.

The report can be created from the TiCore metadata, generated from either A1000 or TiScale.
```python
from rl_threat_hunting.tc_metadata_adapter import parse_tc_metadata

ticore_output  = get_tc_metadata()   # e.g. HTTP request on A1000 or TiScale
hunting_report = parse_tc_metadata(ticore_output)
```

Example of the transformation:
 
<table>
<tr>
<th>TiCore output</th>
<th>Hunting report</th>
</tr>
<tr>
<td>
<pre>
{
  "tc_report": [
    {
      "info": {
        "statistics": {
          "file_stats": [
            {
              "type": "Binary",
              "subtype": "None",
              "count": 48,
              "identifications": [...]
            },
            {
              "type": "Image",
              "subtype": "None",
              "count": 15,
              "identifications": [...]
            },
            {
              "type": "Text",
              "subtype": "XML",
              "count": 1,
              "identifications": [...]
            },
            {
              "type": "PE",
              "subtype": "Exe",
              "count": 1,
              "identifications": [...]
            }
          ]
        },
        "file": {
          "file_type": "PE",
          "file_subtype": "Exe",
          "file_name": "2e577f96b93e520c438180308c2d92eabbf6f410",
          "file_path": "2e577f96b93e520c438180308c2d92eabbf6f410",
          "size": 715776,
          "entropy": 7.861873037781946,
          "hashes": [...]
        },
        "identification": {
          "success": true,
          "name": "ASProtect",
          "version": "1.3x-2.74",
          "author": "ReversingLabs"
        },
        "validation": {...}
      },
      "metadata": {
        "application": {
          "pe": {
            "dos_header": {...},
            "file_header": {...},
            "optional_header": {...},
            "sections": [...],
            "imports": [...],
            "resources": [...],
            "version_info": [...]
          },
          "capabilities": 551221488
        }
      },
      "classification": {
        "propagated": false,
        "classification": 3,
        "factor": 2,
        "scan_results": [
          {
            "type": "internal",
            "classification": 3,
            "factor": 2,
            "name": "TitaniumCore RHA1",
            "version": "3.9.0.0",
            "result": "Win32.Spyware.KGBSpy"
          }
        ]
      },
      "indicators": [...],
      "interesting_strings": [
        {
          "category": "http",
          "values": [
            "l.tf",
            "m.sj",
            "tr.wf",
            "w.gn"
          ]
        },
        {
          "category": "ipv4",
          "values": [
            "1.0.0.0",
            "3.87.38.192",
            "6.0.0.0"
          ]
        }
      ],
      "story": "...",
      "tags": [...],
      "index": 0,
}
</pre>
</td>
<td>
<pre>
{
    "sample_info":{
        "md5":"a71ea666936b4b0d8a2b3d8a083c05ca",
        "sha1":"2e577f96b93e520c438180308c2d92eabbf6f410",
        "sha256":"...",
        "imphash":"622ea142d8a658d32455b258a9cd97ca",
        "filename":"Systems.exe",
        "sample_type":"PE/Exe/ASProtect",
        "sample_size":715776,
        "description":"...",
        "extracted":64,
        "uri":[
            {
                "category":"static_strings",
                "type":"ipv4",
                "value":"3.87.38.192"
            }
        ],
        "pe":{
            "compile_time":708992537,
            "company_name":"ReFog Software",
            "product_name":"KGB Keylogger",
            "original_name":"Systems.exe",
            "section":[...],
            "resource":[...],
            "import":{...}
        },
        "static_analysis_indicators":[...],
        "static_analysis_classification":{
            "classification":"malicious",
            "factor":2,
            "result":"Win32.Spyware.KGBSpy",
            "scanner_result":[
                {
                    "name":"TitaniumCore RHA1",
                    "version":"3.9.0.0",
                    "classification":"malicious",
                    "factor":2,
                    "result":"Win32.Spyware.KGBSpy"
                }
            ]
        },
        "tags":[...],
        "relationships":{
            "children":[]
        },
        "cloud_reputation": {},
        "dynamic_analysis_classification": []
    },
  "cloud_hunting": [...],
  "readable_summary": {...},
}
</pre>
</td>
</tr>
</table>

Main sections of the threat hunting report are:
- `sample_info`: Contains sample's descriptions, identifications and classifications.
- `cloud_hunting`: Collection of *hunting tasks* (queries) that are going to be executed on the cloud APIs.
- `readable_summary`: Human readable classification summary.

In the example above, the `sample_info` will contain information only from TiCore metadata, but as the
hunting progresses, metadata in the `sample_info` will expand with the data from other technologies
(e.g. any RL cloud technology, dynamic analysis, ...).

Based on the `sample_info`, library will generate `cloud_hunting` tasks, which are basically API queries
for various RL cloud technologies (discussed in the following subsections).
Along with the queries, data structures within the `cloud_hunting` section hold responses from the particular
APIs that have been used for the hunting purposes.

Finally, `readable_summary` is part of the hunting report that briefly summarizes classification of the
sample for each state that the report went through. In other words, this field is being constantly updated
as new information is added to the hunting report.

Since static analysis of a sample is not always needed (e.g. for whitelisted files), the first step in the
hunting workflow can be a cloud lookup on the file reputation API. This means that the threat hunting report
can be generated from the response of the file reputation API as well.
```python
from rl_threat_hunting.mwp_metadata_adapter import parse_mwp_metadata

file_reputation = get_file_reputation(sha1)     # HTTP request on the MWP API
hunting_report  = parse_mwp_metadata(file_reputation)
```
<table>
<tr>
<th>MWP Output</th>
<th>Hunting report</th>
</tr>
<tr>
<td>
<pre>
{
    "rl":{
        "entries":[
            {
                "status":"MALICIOUS",
                "sha1":"2e577f96b93e520c438180308c2d92eabbf6f410",
                "threat_level":1,
                "classification":{
                    "platform":"Win32",
                    "type":"PUA",
                    "is_generic":false,
                    "family_name":"KGBFreeKeyLogger"
                },
                "scanner_percent":60.71428680419922,
                "threat_name":"Win32.PUA.KGBFreeKeyLogger",
                "scanner_match":17,
                "last_seen":"2019-02-27T19:10:09",
                "scanner_count":28,
                "query_hash":{
                    "sha1":"2e577f96b93e520c438180308c2d92eabbf6f410"
                },
                "first_seen":"2012-08-09T19:08:00",
                "sha256":"...",
                "trust_factor":5,
                "md5":"a71ea666936b4b0d8a2b3d8a083c05ca"
            }
        ]
    }
}
</pre>
</td>
<td>
<pre>
{
    "sample_info":{
        "md5":"a71ea666936b4b0d8a2b3d8a083c05ca",
        "sha1":"2e577f96b93e520c438180308c2d92eabbf6f410",
        "sha256":"...",     
        "cloud_reputation":{
            "classification":"malicious",
            "threat_name":"Win32.PUA.KGBFreeKeyLogger",
            "factor":1,
            "first_seen":"2012-08-09T19:08:00",
            "last_seen":"2019-02-27T19:10:09",
            "scanner_count":28,
            "scanner_match":17
        }
    },
    "cloud_hunting":[
        {
            "query":{
                "status":"completed",
                "type":"cloud_reputation",
                "term":"2e577f96b93e520c438180308c2d92eabbf6f410",
                "description":"Cloud reputation query determines   \ 
                the threat classification of a given file."
            },
            "malicious":1,
            "classification":"malicious",
            "description":"low threat",
            "threats":[
                {
                    "name":"Win32.PUA.KGBFreeKeyLogger",
                    "description":"...",
                    "factor":1
                }
            ]
        }
    ],
   "readable_summary": {...}
}
</pre>
</td>
</tr>
</table>

A minimal example of how it would look like if workflow would be consisted only from initial file reputation
lookup and the static analysis:
```python
from rl_threat_hunting.mwp_metadata_adapter import parse_mwp_metadata
from rl_threat_hunting.tc_metadata_adapter import parse_tc_metadata

file_reputation = get_file_reputation(sha1)
hunting_report  = parse_mwp_metadata(file_reputation)

if hunting_report['readable_summary']['classification']['classification'] == 'goodware' and \
   hunting_report['readable_summary']['classification']['description'] == 'high trust':
    print('This is goodware. No need for further processing.')
    exit(0)

ticore_output  = get_tc_metadata()
hunting_report = parse_tc_metadata(ticore_output, threat_hunting_state=hunting_report)
```
The same pattern with the `threat_hunting_state` will be reused across library when the hunting report is
passed from one to another hunting step.

### 2.2 Interfaces
Each technology that is used for the threat hunting purposes has to have an interface which is going to
consume and interpret the results that are provided to that interface. Moreover, each interface has a
duty to update current hunting state with the new information and recalculate overall classification.

Interfaces are divided in two groups, cloud interfaces (`rl_threat_hunting.cloud`) for hunting with
the data stored in the RL cloud and local interfaces (`rl_threat_hunting.local`) for hunting
with the data located on the private A1000 instances (hence _local_ in the naming).

Each interface has its own classification algorithm that is used for a specific technology.
Only exception are cloud reputation and local reputation interfaces that can use sam classification
method.
Classification rules are located in the `rl_threat_hunting.result_evaluation` module.

#### File Reputation
File reputation can be done on the cloud data or, if A1000 is available, on the local data.

Dedicated interface for the cloud lookup is wrapped around `update_hunting_meta` function which takes 
hunting report, API response, and task/tasks that triggered the hunting action in the first place.
```python
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.cloud import get_query_tasks
from rl_threat_hunting.cloud import update_hunting_meta

# ...generate hunting_report from TiCore meta

file_reputation_tasks = get_query_tasks(hunting_report, task_type=HuntingCategory.CLOUD_REPUTATION)
for task in file_reputation_tasks:
    api_response = make_mwp_api_request(task)
    
    update_hunting_meta(hunting_report, api_response, task)
``` 
Since file reputation interface allows users to submit a bulk request, the above code can be simplified.
```python
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.cloud import get_query_tasks
from rl_threat_hunting.cloud import update_hunting_meta

# ...generate hunting_report from TiCore meta

file_reputation_tasks = get_query_tasks(hunting_report, task_type=HuntingCategory.CLOUD_REPUTATION)
api_response          = bundle_tasks_and_make_mwp_api_request(file_reputation_tasks)

update_hunting_meta(hunting_report, api_response, *file_reputation_tasks)
``` 
Let's examine all metadata transformations that are going to occur in the simplest case of one file
reputation hunting task.

<table>
<tr>
<th>Before</th>
<th>After</th>
</tr>
<tr>
<td>
<pre>
// hunting_report
{
    "sample_info": {...},
    "cloud_hunting":[
        {
            "query":{
                "status":"pending",
                "type":"cloud_reputation",
                "term":"2e577f96b93e520c438180308c2d92eabbf6f410",
                "description":"Task description."
            }
        },
    "readable_summary": {...}
}
<br>
//api_response
{
    "rl":{
        "entries":[
            {
                "status":"MALICIOUS",
                "sha1":"2e577f96b93e520c438180308c2d92eabbf6f410",
                "threat_level":1,
                "classification":{
                    "platform":"Win32",
                    "type":"PUA",
                    "is_generic":false,
                    "family_name":"KGBFreeKeyLogger"
                },
                "scanner_percent":60.71428680419922,
                "threat_name":"Win32.PUA.KGBFreeKeyLogger",
                "scanner_match":17,
                "last_seen":"2019-02-27T19:10:09",
                "scanner_count":28,
                "query_hash":{
                    "sha1":"2e577f96b93e520c438180308c2d92eabbf6f410"
                },
                "first_seen":"2012-08-09T19:08:00",
                "sha256":"...",
                "trust_factor":5,
                "md5":"a71ea666936b4b0d8a2b3d8a083c05ca"
            }
        ]
    }
}
<br>
// task
{
    "query":{
        "status":"pending",
        "type":"cloud_reputation",
        "term":"2e577f96b93e520c438180308c2d92eabbf6f410",
        "description":"Task description."
    }
}
</pre>
</td>
<td>
<pre>
{
    "sample_info":{
        "cloud_reputation":{
            "classification":"malicious",
            "threat_name":"Win32.PUA.KGBFreeKeyLogger",
            "factor":1,
            "first_seen":"2012-08-09T19:08:00",
            "last_seen":"2019-02-27T19:10:09",
            "scanner_count":28,
            "scanner_match":17
        },
        "sha256":"...",
        "sha1":"2e577f96b93e520c438180308c2d92eabbf6f410",
        "md5":"a71ea666936b4b0d8a2b3d8a083c05ca"
    },
    "cloud_hunting":[
        {
            "query":{
                "status":"completed",
                "type":"cloud_reputation",
                "term":"2e577f96b93e520c438180308c2d92eabbf6f410",
                "description":"Task description."
            },
            "malicious":1,
            "classification":"malicious",
            "description":"low threat",
            "threats":[
                {
                    "name":"Win32.PUA.KGBFreeKeyLogger",
                    "description":"Description of the threat.",
                    "factor":1
                }
            ]
        }
    ],
    "readable_summary":{
        "classification":{
            "classification":"malicious",
            "description":"low threat",
            "reason":"Hash based lookup (sha1: 2e577f96b93e520c438180308c2d92eabbf6f410) \
            on TiCloud file reputation API.",
            "threat":{
                "name":"Win32.PUA.KGBFreeKeyLogger",
                "description":"Description of the threat.",
                "factor":1
            }
        },
        "sample":{...},
        "cloud_hunting":{
            "cloud_reputation":{
                "pending":0,
                "skipped":0,
                "completed":1,
                "failed":0
            },
            "certificate_analytics":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "file_similarity_analytics":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "uri_analytics":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "search":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            }
        },
        "local_hunting":[],
        "att&ck":[]
    }
}
</pre>
</td>
</tr>
</table>

Along the cloud file reputation interface, library supports local A1000 file reputation
interface implemented in the `rl_threat_hunting.local_reputation` module.
The main function that processes local file reputation information is `process_local_reputation`.
What is special about the function is that it takes API request function object as a parameter.
Take a look at function's doc string for argument descriptions.
```python
def process_local_reputation(api_request_function, samples_meta, hunting_state=None):
    """
    :param api_request_function: Request function on /api/samples/list/details/ endpoint on the A1000.
                                 Function will fetch classification meta for multiple samples.
                                 Function takes list of hashes as an argument.
    :param samples_meta: One or more instances of the TC metadata or the Child class.
                         If Child objects are passed, TC metadata is extracted from them.
    :param hunting_state: Threat hunting state from previous hunting steps.
                          The cloud_reputation section will be updated if there is an user override.
    :return: Enriched TC metadata with cloud reputation or local A1000 user override.
    """
```
> Child class will be explained later.

Typical set of instructions that are used for processing local file reputation is following.
```python
from rl_threat_hunting.local_reputation import process_local_reputation
from rl_threat_hunting.tc_metadata_adapter import parse_tc_metadata

def make_local_file_reputation_request(list_of_hash_values):
    pass

ticore_output          = get_tc_metadata_from_a1000()
expanded_ticore_output = process_local_reputation(make_local_file_reputation_request, ticore_output)
hunting_report         = parse_tc_metadata(expanded_ticore_output)
```
> Keep in mind that for the local file reputation, an A1000 instance must be available.
>
> For complete implementation of the `make_local_file_reputation_request` method take a look
> at the `tests/test_a1000_local_reputation.py` script.



#### File Similarity
File similarity is technology only available in the RL cloud.

Dedicated interface for the cloud lookup is wrapped around `update_hunting_meta` function which takes 
hunting report, API response, and task/tasks that triggered the hunting action in the first place.
```python
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.cloud import get_query_tasks
from rl_threat_hunting.cloud import update_hunting_meta

# ...generate hunting_report from TiCore meta

file_similarity_tasks = get_query_tasks(hunting_report, task_type=HuntingCategory.FILE_SIMILARITY_ANALYTICS)
for task in file_similarity_tasks:
    api_response = make_rha1_api_request(task)
    
    update_hunting_meta(hunting_report, api_response, task)
``` 
Since file similarity interface allows users to submit a bulk request, the above code can be simplified.
```python
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.cloud import get_query_tasks
from rl_threat_hunting.cloud import update_hunting_meta

# ...generate hunting_report from TiCore meta

file_similarity_tasks = get_query_tasks(hunting_report, task_type=HuntingCategory.FILE_SIMILARITY_ANALYTICS)
api_response          = bundle_tasks_and_make_mwp_api_request(file_similarity_tasks)

update_hunting_meta(hunting_report, api_response, *file_similarity_tasks)
``` 
Let's examine all metadata transformations that are going to occur in the simplest case of one file
similarity hunting task.
<table>
<tr>
<th>Before</th>
<th>After</th>
</tr>
<tr>
<td>
<pre>
// hunting_report
{
    "sample_info": {...},
    "cloud_hunting":[
        {
            "query":{
                "status":"pending",
                "type":"file_similarity_analytics",
                "term":"pe01/26fa405c21f53e95fe979c287ea13fe3355d798a",
                "description":"Task description."
            }
        },
    "readable_summary": {...}
}
<br>
//api_response
{
    "rl": {
        "entries": [
            {
                "sha1": "26fa405c21f53e95fe979c287ea13fe3355d798a",
                "rha1_type": "pe01",
                "rha1_first_seen": 1424142780000,
                "rha1_last_seen": 1461535439221,
                "sample_counters": {
                    "known": 0,
                    "malicious": 21,
                    "suspicious": 6,
                    "total": 27
                },
                "sample_metadata": {
                    "md5": "b603a1ef9d689267155bd0294e180ed9",
                    "sha256": "...",
                    "classification": "MALICIOUS",
                    "sample_type": "PE/.Net Exe",
                    "sample_size": 126976,
                    "sample_available": true,
                    "trust_factor": 5,
                    "threat_level": 5,
                    "threat_name": "ByteCode-MSIL.Backdoor.NanoCore",
                    "malware_family": "NanoCore",
                    "malware_type": "Backdoor",
                    "platform": "ByteCode",
                    "subplatform": "MSIL",
                    "first_seen": "2015-04-14T01:06:00",
                    "last_seen": "2019-12-24T17:24:37.645000"
                }
            }
        ]
    }
}
<br>
// task
{
    "query":{
        "status":"pending",
        "type":"file_similarity_analytics",
        "term":"pe01/26fa405c21f53e95fe979c287ea13fe3355d798a",
        "description":"Task description."
    }
}
</pre>
</td>
<td>
<pre>
{
    "sample_info":{...},
    "cloud_hunting":[
        {
            "query":{
                "status":"completed",
                "type":"file_similarity_analytics",
                "term":"pe01/26fa405c21f53e95fe979c287ea13fe3355d798a",
                "description":"Task description."
            },
            "malicious":27,
            "classification":"malicious",
            "description":"high threat"
        }
    ],
    "readable_summary":{
        "classification":{
            "classification":"malicious",
            "description":"high threat",
            "reason":"File similarity hash lookup (pe01/26fa405c21f53e95fe979c287ea13fe3355d798a) \
            shows that file is similar to known malware.",
            "threat":{
                "name":null,
                "description":null,
                "factor":null
            }
        },
        "sample":{...},
        "cloud_hunting":{
            "cloud_reputation":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "certificate_analytics":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "file_similarity_analytics":{
                "pending":0,
                "skipped":0,
                "completed":1,
                "failed":0
            },
            "uri_analytics":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "search":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            }
        },
        "local_hunting":{},
        "att&ck":[...]
    }
}
</pre>
</td>
</tr>
</table>

#### URI Statistics
URI statistics is technology only available in the RL cloud.

Dedicated interface for the cloud lookup is wrapped around `update_hunting_meta` function which takes 
hunting report, API response, and task/tasks that triggered the hunting action in the first place.
```python
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.cloud import get_query_tasks
from rl_threat_hunting.cloud import update_hunting_meta

# ...generate hunting_report from TiCore meta

uri_statistics_tasks = get_query_tasks(hunting_report, task_type=HuntingCategory.URI_ANALYTICS)
for task in uri_statistics_tasks:
    api_response = make_uri_api_request(task)
    
    update_hunting_meta(hunting_report, api_response, task)
``` 
> Bulk query is not available on URI Statistics API.
 
Let's examine all metadata transformations that are going to occur in the simplest case of one URI
statistics hunting task.
<table>
<tr>
<th>Before</th>
<th>After</th>
</tr>
<tr>
<td>
<pre>
// hunting_report
{
    "sample_info": {...},
    "cloud_hunting":[
        {
            "query":{
                "status":"completed",
                "type":"uri_analytics",
                "term":"http://www.w3.org/1998/Math/MathML",
                "description":"Task description."
            }
        },
    "readable_summary": {...}
}
<br>
//api_response
{
    "rl": {
        "uri_state": {
            "url": "http://www.w3.org/1998/Math/MathML",
            "sha1": "6073ea7b91aa5adc6387e3392bbd908836fa470e",
            "uri_type": "url",
            "counters": {
                "known": 2064721,
                "malicious": 71992,
                "suspicious": 3007
            }
        }
    }
}
<br>
// task
{
    "query":{
        "status":"pending",
        "type":"file_similarity_analytics",
        "term":"pe01/26fa405c21f53e95fe979c287ea13fe3355d798a",
        "description":"Task description."
    }
}
</pre>
</td>
<td>
<pre>
{
    "sample_info":{...},
    "cloud_hunting":[
        {
            "query":{
                "status":"completed",
                "type":"uri_analytics",
                "term":"http://www.w3.org/1998/Math/MathML",
                "description":"Task description."
            },
            "classification":"undecided",
            "description":"not enough data"
        },
    ],
    "readable_summary":{
        "classification":{
            "classification":"undecided",
            "description":"not enough data",
            "reason":"File contains URI (http://www.w3.org/1998/Math/MathML) \
            related to known malicious content.",
            "threat":{
                "name":null,
                "description":null,
                "factor":null
            }
        },
        "sample":{...},
        "cloud_hunting":{
            "cloud_reputation":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "certificate_analytics":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "file_similarity_analytics":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "uri_analytics":{
                "pending":0,
                "skipped":0,
                "completed":1,
                "failed":0
            },
            "search":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            }
        },
        "local_hunting":{},
        "att&ck":[...]
    }
}
</pre>
</td>
</tr>
</table>

#### Certificate Analytics
Certificate analytics is technology only available in the RL cloud.

Dedicated interface for the cloud lookup is wrapped around `update_hunting_meta` function which takes 
hunting report, API response, and task/tasks that triggered the hunting action in the first place.
```python
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.cloud import get_query_tasks
from rl_threat_hunting.cloud import update_hunting_meta

# ...generate hunting_report from TiCore meta

cert_analytics_tasks = get_query_tasks(hunting_report, task_type=HuntingCategory.CERTIFICATE_ANALYTICS)
for task in cert_analytics_tasks:
    api_response = make_certificate_api_request(task)
    
    update_hunting_meta(hunting_report, api_response, task)
``` 

Since certificate analytics interface allows users to submit a bulk request, the above code can be simplified.
```python
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.cloud import get_query_tasks
from rl_threat_hunting.cloud import update_hunting_meta

# ...generate hunting_report from TiCore meta

cert_analytics_tasks = get_query_tasks(hunting_report, task_type=HuntingCategory.CERTIFICATE_ANALYTICS)
api_response          = bundle_tasks_and_make_mwp_api_request(cert_analytics_tasks)

update_hunting_meta(hunting_report, api_response, *cert_analytics_tasks)
```
 
Let's examine all metadata transformations that are going to occur in the simplest case of one certificate
analytics hunting task.
<table>
<tr>
<th>Before</th>
<th>After</th>
</tr>
<tr>
<td>
<pre>
// hunting_report
{
    "sample_info": {...},
    "cloud_hunting":[
        {
            "query":{
                "status":"pending",
                "type":"certificate_analytics",
                "term":"3a0682ab7fb478ba82fd11ce4db9b0adea55da05558a0cf737453d51572163d0",
                "description":"Task description."
            }
        }
    "readable_summary": {...}
}
<br>
//api_response
{
    "rl": {
        "request": {
            "response_format": "json",
            "thumbprints": [
                "3a0682ab7fb478ba82fd11ce4db9b0adea55da05558a0cf737453d51572163d0"
            ]
        },
        "certificate_analytics": [
            {
                "certificate_first_seen": "2015-02-19T10:39:09",
                "statistics": {
                    "known": 51,
                    "unknown": 0,
                    "malicious": 0,
                    "suspicious": 0,
                    "total": 51
                },
                "classification": {
                    "status": "undefined"
                },
                "certificate": {...}
            }
        ]
    }
}
<br>
// task
{
    "query":{
        "status":"pending",
        "type":"certificate_analytics",
        "term":"3a0682ab7fb478ba82fd11ce4db9b0adea55da05558a0cf737453d51572163d0",
        "description":"Task description."
    }
}
</pre>
</td>
<td>
<pre>
{
    "sample_info":{...},
    "cloud_hunting":[
        {
            "query":{
                "status":"completed",
                "type":"certificate_analytics",
                "term":"3a0682ab7fb478ba82fd11ce4db9b0adea55da05558a0cf737453d51572163d0",
                "description":"Task description."
            },
            "malicious":0,
            "classification":"goodware",
            "description":"low trust"
        },
    ],
    "readable_summary":{
        "classification":{
            "classification":"goodware",
            "description":"low trust",
            "reason":"File is signed with whitelisted certificate \ 
            (thumbprint: 3a0682ab7fb478ba82fd11ce4db9b0adea55da05558a0cf737453d51572163d0).",
            "threat":{
                "name":null,
                "description":null,
                "factor":null
            }
        },
        "sample":{...},
        "cloud_hunting":{
            "cloud_reputation":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "certificate_analytics":{
                "pending":0,
                "skipped":0,
                "completed":1,
                "failed":0
            },
            "file_similarity_analytics":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "uri_analytics":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "search":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            }
        },
        "local_hunting":{},
        "att&ck":[...]
    }
}
</pre>
</td>
</tr>
</table>

#### Advanced Search
Advanced Search is technology available both in the RL cloud and an A1000 instance.

Dedicated interface for the cloud lookup is wrapped around `update_hunting_meta` function which takes 
hunting report, API response, and task/tasks that triggered the hunting action in the first place.
```python
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.cloud import get_query_tasks
from rl_threat_hunting.cloud import update_hunting_meta

# ...generate hunting_report from TiCore meta

search_tasks = get_query_tasks(hunting_report, task_type=HuntingCategory.ADVANCED_SEARCH)
for task in search_tasks:
    api_response = make_advanced_search_api_request(task)
    
    update_hunting_meta(hunting_report, api_response, task)
```
 
Let's examine all metadata transformations that are going to occur in the simplest case of one certificate
analytics hunting task.
<table>
<tr>
<th>Before</th>
<th>After</th>
</tr>
<tr>
<td>
<pre>
// hunting_report
{
    "sample_info": {...},
    "cloud_hunting":[
        {
            "query":{
                "status":"pending",
                "type":"search",
                "term":"email-from:ynsoguz94@yandex.com AND                 \
                ((classification:malicious AND                              \
                tag:email-attachment) OR                                    \
                (tag:email-subject-spam OR                                  \
                tag:email-subject-phishing OR                               \
                tag:email-impersonation OR tag:email-deceptive-sender))",
                "description":"Task description."
            },
        }
    "readable_summary": {...}
}
<br>
//api_response
{
    "rl": {
        "web_search_api": {
            "more_pages": true,
            "total_count": 257,
            "next_page": 2,
            "sample_count": 0,
            "entries": []
        }
    }
}
<br>
// task
{
    "query":{
        "status":"pending",
        "type":"search",
        "term":"email-from:ynsoguz94@yandex.com AND                 \
        ((classification:malicious AND                              \
        tag:email-attachment) OR                                    \
        (tag:email-subject-spam OR                                  \
        tag:email-subject-phishing OR                               \
        tag:email-impersonation OR tag:email-deceptive-sender))",
        "description":"Task description."                     
    },
}
</pre>
</td>
<td>
<pre>
{
    "sample_info":{...},
    "cloud_hunting":[
        {
            "query":{
                "status":"completed",
                "type":"search",
                "term":"email-from:ynsoguz94@yandex.com AND                 \
                ((classification:malicious AND                              \
                tag:email-attachment) OR                                    \
                (tag:email-subject-spam OR                                  \
                tag:email-subject-phishing OR                               \
                tag:email-impersonation OR tag:email-deceptive-sender))",
                "description":"Task description."
            },
            "malicious":142,
            "classification":"malicious",
            "description":"low threat",
            "threats":[
                {
                    "name":"Win32.Trojan.Digitul",
                    "description":"Threat description.",
                    "factor":5
                },
                {
                    "name":"Script.Virus.Zibbert",
                    "description":"Threat description.",
                    "factor":5
                },
                {
                    "name":"Win32.Virus.Induc",
                    "description":"Threat description.",
                    "factor":5
                },
                {
                    "name":"Win32.Virus.Alia",
                    "description":"Threat description.",
                    "factor":5
                },
                {
                    "name":"Script.Virus.Trivial",
                    "description":"Threat description.",
                    "factor":5
                }
            ]
        },
    ],
    "readable_summary":{
        "classification":{
            "classification":"malicious",
            "description":"low threat",
            "reason":"File contains indicator that is usually found       \ 
            malicious samples.                                            \
            Search query: \"email-from:ynsoguz94@yandex.com AND           \
            ((classification:malicious AND tag:email-attachment) OR       \
            (tag:email-subject-spam OR tag:email-subject-phishing OR      \
            tag:email-impersonation OR tag:email-deceptive-sender))\".",
            "threat":{
                "name":"Win32.Trojan.Digitul",
                "description":"Threat description.",
                "factor":5
            }
        },
        "sample":{...},
        "cloud_hunting":{
            "cloud_reputation":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "certificate_analytics":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "file_similarity_analytics":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "uri_analytics":{
                "pending":0,
                "skipped":0,
                "completed":0,
                "failed":0
            },
            "search":{
                "pending":0,
                "skipped":0,
                "completed":1,
                "failed":0
            }
        },
        "local_hunting":{
            "search":{
                "pending":0,
                "skipped":1,
                "completed":0,
                "failed":0
            }
        },
        "att&ck":[...]
    }
}
</pre>
</td>
</tr>
</table>

##### StopIteration
The `StopIteration` exception is raised when the first malicious result is processed
from the Advanced Search API.
This exception must be handled.
Also, it can be used to make an early exit from the hunting routine since malicious
indicators are found and there is no need for further processing.
```python
from rl_threat_hunting.constants import HuntingCategory
from rl_threat_hunting.cloud import get_query_tasks
from rl_threat_hunting.cloud import update_hunting_meta

# ...generate hunting_report from TiCore meta

early_exit = True

search_tasks = get_query_tasks(hunting_report, task_type=HuntingCategory.ADVANCED_SEARCH)
for task in search_tasks:
    api_response = make_advanced_search_api_request(task)
    
    try:
        update_hunting_meta(hunting_report, api_response, task)
    except StopIteration:
        if early_exit:
            break
```  


##### Two types of search tasks
Even though they all look the same, search tasks can be divided in two types.
One type of tasks has `classification:malicious` string within search term and
it is comprised from multiple search fields and the other one doesn't have the
`classification:malicious` string and it is consisted only from single search field.

First type is fairly simple to use. The search term is forwarded to the function that
makes API requests on the Advanced Search endpoint and results are further passed into
the library (same as shown in the example above).

Second type is a bit more complex. This type of search task has to be executed two times.
The first time, a search term should be expanded with the `AND classification:malicious`
search filed and the second time, a search term should be expanded with the 
`AND classification:known`.
Results for each variant of the search request should be bundled into a tuple and passed
to the advanced search interface.
**Note**, order of results in the bundle should always be malicious first, than known.

The reason why is necessary to execute the same task twice is because if the task is
executed only once, without `classification` field, the number of matches (samples)
will not be distinguished by their classification, thus make it impossible to produce
classification for a sample that is analysed within the threat hunting routine.

Check the example bellow.

Let's assume that the search request will be posed on the API for the following search task:
```
{
    "query":{
        "status":"pending",
        "type":"search",
        "term":"pe-function:initializecriticalsectionandspincount",
        "description":"Searching for PE files by API-related metadata they contain."
    },
}
```
A code snippet describing how to properly form search queries and how to bundle the results.
```python
task = {...}   # displayed above

search_term = 'pe-function:initializecriticalsectionandspincount'

first_search  = search_term + 'AND classification:malicious'
second_search = search_term + 'AND classification:known'

first_response  = make_advanced_search_api_request(first_search)
second_response = make_advanced_search_api_request(second_search)

api_response = (first_response, second_response)

update_hunting_meta(hunting_report, api_response, task)
```

##### Search (informative)
There is also a type of search tasks that are not executed during the hunting routine and
they could be recognized by the query type: 

```
{
    "query":{
        "status":"skipped",
        "type":"search (informative)",
        "term":"(pe-section-sha1:b26a1838c2fda9e6cbc137d908bfe51ee31d0551 OR 
        pe-section-sha1:19d0f02074943cd9cccfb8171d9921e90ce26007 OR 
        pe-section-sha1:0ef4d2ee556afabe3e4149b08cde9e946510c609 OR 
        pe-section-sha1:32af62e6fbeffdb4372101aa04049f3c5ec1b48d OR 
        pe-section-sha1:82da9df52081010204d2b23a70f611d7909420df OR 
        pe-section-sha1:fecad3dae95fe4fd9a7cbd61515b9edebe51f976 OR 
        pe-section-sha1:aa0d33a0c854e073439067876e932688b65cb6a9 OR 
        pe-section-sha1:2155bfba492c02a180b447f1a905f4b382eccf62) AND 
        (classification:malicious AND NOT threatname:*.Virus*)",
        
        "description":"Searching for PE files by hashes of the sections they contain. Also searching for strictly non-polymorphic malicious files.",
        "propagated":"e399ad305160fb2c263c0b650225ec88b29f1b78"
    }
},
```

These tasks a user can execute after the threat hunting to augment metadata collected
during the hunting routine.

##### Be aware!
Be aware that library generates search tasks only for predefined set of search fields.

Be aware that library pre-filters all search term candidates and rules out each
search term that is recognized as _common_, i.e. it is listed in any of modules located
within the `rl_threat_hunting.filter`.
For specific implementation of each filter, please visit dedicated
[confluence page](https://alt-confluence.rl.lan/display/TCEP/Sample+info+metadata+selection+details).

#### Task Status
Each task has four possible states: pending, completed, skipped and failed.

Pending and completed states are straight forward.

A task will receive **skipped** state when final classification is achieved.
And the classification is proclaimed finial when a sample is whitelisted or malicious.
There is no point in proceeding with the hunting if any of these conditions are met.
This state is set automatically within the library.

A task will receive **failed** state when error happens during the API request.
Only caveat is that this state should be set by the function that makes API request.
Check the code snippet bellow.
```python
from rl_threat_hunting.cloud import mark_tasks_as_failed

# ...generate hunting_report from TiCore meta

file_reputation_tasks = get_query_tasks(hunting_report, task_type=HuntingCategory.CLOUD_REPUTATION)
for task in file_reputation_tasks:
    try:
        api_response = make_mwp_api_request(task)
    except (HTTPError, ConnectionError):            # any other related error
        mark_tasks_as_failed(hunting_meta, task)
        continue
    
    update_hunting_meta(hunting_report, api_response, task)


####### BULK VARIANT ########

from rl_threat_hunting.cloud import mark_tasks_as_failed

# ...generate hunting_report from TiCore meta

file_reputation_tasks = get_query_tasks(hunting_report, task_type=HuntingCategory.CLOUD_REPUTATION)

try:
    api_response = bundle_tasks_and_make_mwp_api_request(file_reputation_tasks)
except (HTTPError, ConnectionError):            # any other related error
    mark_tasks_as_failed(hunting_report, *file_reputation_tasks)
    raise  # or return

update_hunting_meta(hunting_report, api_response, *file_reputation_tasks)
```

### 2.3 Plugins
Plugins are used for consuming metadata from services that are not embedded into hunting workflow such as the services
discussed in the previous section. Currently, only dynamic analysis plugins are supported. One for Joe Sandbox engine
(`joe_sandbox.py`) and one for RL Cloud Dynamic Analysis service (`cloud_dynamic_analysis.py`).

For implementation details please check the source and for an example how to use these plugins, check the code snippet
bellow.
```python
# Example with Joe Sandbox plugin

from rl_threat_hunting.plugins import joe_sandbox

# ...generate hunting_report from TiCore meta

joe_metadata = fetch_joe_report(report_id)
joe_sandbox.add_dynamic_analysis(hunting_report, joe_metadata)


# Example with Joe Sandbox plugin

from rl_threat_hunting.plugins import cloud_dynamic_analysis

# ...generate hunting_report from TiCore meta

dynamic_analysis_metadata = fetch_rl_dynamic_analysis_meta(sha1, report_id)
cloud_dynamic_analysis.add_dynamic_analysis(hunting_report, dynamic_analysis_metadata)
```

Finally, after successful execution of plugin methods, the `sample_info` section of the hunting report will have a
`dynamic_analysis_classification` key with corresponding classification from the dynamic analysis engine. An example of
such report is presented bellow.
```json
{
  "sample_info": {
    // ...
    "dynamic_analysis_classification": [
      {
        "name": "Cloud Dynamic Analysis", 
        "classification": "MALICIOUS"
      }
    ],
    // ...
  },
  // ...
}
```

If metadata from dynamic analysis services/engines is used for the hunting purposes it will affect overall threat hunting
classification. Be careful when using these services within hunting workflow because some of them (e.g. Joe Sandbox) can
have RL Cloud integration configured which will result in a positive classification feedback loop with false
classification as a result.

**Note**. Currently, only final classification from dynamic analysis services will be used for hunting purposes.
