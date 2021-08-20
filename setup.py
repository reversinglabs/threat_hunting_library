
from setuptools import setup


setup(name='python-rl_threat_hunting',
      version='1.588',
      license="MIT",
      description='ReversingLabs TC team threat hunting library',
      packages=[
          'rl_threat_hunting',
          'rl_threat_hunting.adapter',
          'rl_threat_hunting.cloud',
          'rl_threat_hunting.local',
          'rl_threat_hunting.filter',
          'rl_threat_hunting.plugins'
      ],
      install_requires ='tldextract',
      build_requires   ='GitPython')
