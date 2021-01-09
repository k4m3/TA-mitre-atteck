
# encoding = utf-8
# Always put this line at the beginning of this file
import ta_mitre_atteck_declare

import os
import sys

from alert_actions_base import ModularAlertBase
import modalert_mitre_att_ck_helper

class AlertActionWorkermitre_att_ck(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkermitre_att_ck, self).__init__(ta_name, alert_name)

    def validate_params(self):

        if not self.get_global_setting("index_summary_alert"):
            self.log_error('index_summary_alert is a mandatory setup parameter, but its value is None.')
            return False

        if not self.get_param("summary_log"):
            self.log_error('summary_log is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("tactics"):
            self.log_error('tactics is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("technique"):
            self.log_error('technique is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("data_source"):
            self.log_error('data_source is a mandatory parameter, but its value is None.')
            return False
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_mitre_att_ck_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error("Error: {}. Please double check spelling and also verify that a compatible version of Splunk_SA_CIM is installed.".format(str(ae)))
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if e:
                self.log_error(msg.format(str(e)))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status

if __name__ == "__main__":
    exitcode = AlertActionWorkermitre_att_ck("TA-mitre-atteck", "mitre_att_ck").run(sys.argv)
    sys.exit(exitcode)
