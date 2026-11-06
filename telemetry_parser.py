import json
import os
import xml.etree.ElementTree as ET
import pandas as pd


class CyberionTelemetryParser:
    """
    Unified Data Ingestion Engine for Cyberion Defense Labs.
    Normalizes Mordor JSON, Splunk BOTS CSV, and XML Event dataframes.
    """

    def __init__(self):
        self.unified_columns = ['timestamp', 'event_id', 'process_name', 'cmd_line', 'parent_process', 'target_object',
                                'user']

    def parse_mordor_json(self, file_path: str) -> pd.DataFrame:
        """Parses Mordor JSON/OSSEM pre-recorded adversary simulation datasets."""
        parsed_records = []
        if not os.path.exists(file_path):
            print(f"[!] Path Error: File not found at {file_path}")
            return pd.DataFrame(columns=self.unified_columns)

        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip(): continue
                data = json.loads(line)
                event_data = data.get('event_data', {})
                record = {
                    'timestamp': data.get('@timestamp'),
                    'event_id': str(data.get('event_id', '')),
                    'process_name': event_data.get('SourceImage') or event_data.get('Image'),
                    'cmd_line': event_data.get('CommandLine'),
                    'parent_process': event_data.get('ParentImage'),
                    'target_object': event_data.get('TargetImage'),
                    'user': event_data.get('User')
                }
                parsed_records.append(record)
        df = pd.DataFrame(parsed_records)
        return df.reindex(columns=self.unified_columns)

    def parse_splunk_bots_csv(self, file_path: str) -> pd.DataFrame:
        """Parses Splunk BOTS CIM normalized data exports."""
        if not os.path.exists(file_path):
            print(f"[!] Path Error: File not found at {file_path}")
            return pd.DataFrame(columns=self.unified_columns)

        df = pd.read_csv(file_path)
        normalized_df = pd.DataFrame()

        normalized_df['timestamp'] = df['_time'] if '_time' in df.columns else None
        if 'EventCode' in df.columns:
            normalized_df['event_id'] = df['EventCode'].fillna(-1).astype(int).astype(str).replace('-1', '')
        else:
            normalized_df['event_id'] = ''

        normalized_df['process_name'] = df['process_path'] if 'process_path' in df.columns else None
        normalized_df['cmd_line'] = df['process'] if 'process' in df.columns else None
        normalized_df['parent_process'] = df['parent_process_path'] if 'parent_process_path' in df.columns else None
        normalized_df['target_object'] = df['file_name'] if 'file_name' in df.columns else None
        normalized_df['user'] = df['user'] if 'user' in df.columns else None

        return normalized_df.reindex(columns=self.unified_columns)

    def parse_mock_evtx_xml(self, file_path: str) -> pd.DataFrame:
        """Parses XML-structured Windows event telemetry dumps."""
        if not os.path.exists(file_path):
            print(f"[!] Path Error: File not found at {file_path}")
            return pd.DataFrame(columns=self.unified_columns)

        tree = ET.parse(file_path)
        root = tree.getroot()
        ns = {'ns': 'http://microsoft.com'}

        system = root.find('ns:System', ns)
        event_data = root.find('ns:EventData', ns)

        event_id = system.find('ns:EventID', ns).text if system is not None else ""
        time_created = system.find('ns:TimeCreated', ns).attrib.get('SystemTime') if system is not None else None

        data_dict = {}
        if event_data is not None:
            for data in event_data.findall('ns:Data', ns):
                name = data.attrib.get('Name')
                if name:
                    data_dict[name] = data.text

        record = {
            'timestamp': time_created,
            'event_id': str(event_id),
            'process_name': data_dict.get('SourceImage') or data_dict.get('Image'),
            'cmd_line': data_dict.get('CommandLine'),
            'parent_process': data_dict.get('ParentImage'),
            'target_object': data_dict.get('TargetImage'),
            'user': data_dict.get('User')
        }
        return pd.DataFrame([record]).reindex(columns=self.unified_columns)
