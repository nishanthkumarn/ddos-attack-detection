from fastapi.testclient import TestClient
from app.main import app

def test_health():
    with TestClient(app) as c:
        r=c.get('/health'); assert r.status_code==200; assert r.json()['status']=='ok'

def test_predict():
    with TestClient(app) as c:
        r=c.post('/api/predict',json={'features':{'pps':50000,'bps':10000000}})
        assert r.status_code==200; assert r.json()['label'] in {'BENIGN','DDoS'}

def test_evaluate_labeled_csv_reports_confusion_counts(monkeypatch):
    from app.main import detector

    async def idle_stream(stop_event):
        await stop_event.wait()

    def fake_predict(features):
        probability = 0.9 if float(features['Flow Packets/s']) >= 100 else 0.1
        label = 'DDoS' if probability >= detector.threshold else 'BENIGN'
        return label, probability, max(probability, 1-probability), 'HIGH', [], 'model'

    monkeypatch.setattr(detector, 'model', object())
    monkeypatch.setattr(detector, 'predict', fake_predict)
    monkeypatch.setattr('app.main.stream_loop', idle_stream)
    content = (
        b'Src IP,Dst IP,Protocol,Flow Packets/s,Flow Bytes/s,Flow Duration,Total Fwd Packets,Total Backward Packets,Label\n'
        b'10.0.0.1,10.0.0.2,TCP,10,1000,100,10,5,BENIGN\n'
        b'10.0.0.3,10.0.0.2,UDP,500,50000,100,50,0,DrDoS_DNS\n'
        b'10.0.0.4,10.0.0.2,TCP,10,1000,100,10,5,SYN\n'
        b'10.0.0.5,10.0.0.2,TCP,10,1000,100,10,5,NORMAL\n'
    )

    with TestClient(app) as client:
        response = client.post(
            '/api/evaluate/csv',
            files={'file': ('flows.csv', content, 'text/csv')},
        )

    assert response.status_code == 200
    result = response.json()
    assert result['rows'] == 4
    assert result['metrics']['confusion_matrix'] == {'tn': 2, 'fp': 0, 'fn': 1, 'tp': 1}
    assert result['attack_families'] == [
        {'label': 'DrDoS_DNS', 'rows': 1, 'recall': 1.0},
        {'label': 'SYN', 'rows': 1, 'recall': 0.0},
    ]
    assert result['results'][1]['src_ip'] == '10.0.0.3'
    assert result['results'][3]['actual_class'] == 'BENIGN'


def test_evaluate_csv_requires_label_column():
    with TestClient(app) as client:
        response = client.post(
            '/api/evaluate/csv',
            files={'file': ('flows.csv', b'Flow Packets/s\n100\n', 'text/csv')},
        )

    assert response.status_code == 422


def test_synthesized_flow_includes_protocol_and_ports():
    from app.main import detector

    features = detector.synthesize_flow_vector(
        {'protocol': 'UDP', 'src_port': 53000, 'dst_port': 53}
    )

    assert features['Protocol'] == 17.0
    assert features['Source Port'] == 53000.0
    assert features['Destination Port'] == 53.0
