import logging
from api.main import check_for_threats

logging.basicConfig(level=logging.DEBUG)
print("Starting pipeline test...")
check_for_threats()
print("Pipeline test finished!")
