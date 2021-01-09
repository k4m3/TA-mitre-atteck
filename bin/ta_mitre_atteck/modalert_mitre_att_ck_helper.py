
# encoding = utf-8

def process_event(helper, *args, **kwargs):
    
    index_summary_alert = helper.get_param("index_summary_alert")
    summary_log = helper.get_param("summary_log")
    tactics = helper.get_param("tactics")
    technique = helper.get_param("technique")
    data_source = helper.get_param("data_source")
    
    summary_log = "Name=\"" +summary_log+ "\" Tactics=\"" +tactics+ "\" Technique=\"" +technique+ "\" Data_Source=\"" +data_source+ "\""
    
    helper.addevent(summary_log, sourcetype="MITRE ATT&CK")
    helper.writeevents(index=index_summary_alert, host="SPLK MITRE ACTION", source="MITRE ATT&CK")
    
    print(summary_log)
    
    helper.log_info("Alert action mitre_att_ck started.")

    return 0
