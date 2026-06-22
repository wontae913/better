import boto3
import csv
import re

def load_mapping_table(csv_path):
    """SG 참조 매핑 테이블을 로드합니다."""
    mapping = {}
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                src = row['source_id'].strip()
                tgt = row['target_id'].strip()
                if src and tgt:
                    mapping[src] = tgt
        print(f"ℹ️ 매핑 테이블 로드 완료 ({len(mapping)}개 항목)")
    except FileNotFoundError:
        print(f"⚠️ 매핑 파일({csv_path})이 없습니다. SG 참조 규칙은 제외될 수 있습니다.")
    return mapping

def parse_value_with_desc(val):
    """
    AWS CSV의 '값 (설명)' 포맷을 분리합니다.
    예: '58.151.93.0/27 (ssh_bespin)' -> ('58.151.93.0/27', 'ssh_bespin')
    """
    if not val:
        return None, None
    
    val = val.strip()
    # 공백을 기준으로 첫 번째 값(IP, SG ID 등)과 나머지(설명)를 분리
    parts = val.split(' ', 1)
    target_value = parts[0]
    description = ""
    
    if len(parts) > 1:
        # 정규식으로 괄호 안의 텍스트만 추출
        match = re.search(r'\((.*?)\)', parts[1])
        if match:
            description = match.group(1)
            
    return target_value, description

def import_sg_from_aws_csv(aws_csv_path, mapping_csv_path, target_vpc_id, region):
    ec2 = boto3.client('ec2', region_name=region)
    mapping_table = load_mapping_table(mapping_csv_path)
    
    # 1. AWS CSV 파일 읽기
    rules = []
    with open(aws_csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rules.append(row)
            
    if not rules:
        print("❌ CSV 파일에 규칙이 없습니다.")
        return

    # 2. 첫 번째 행에서 보안그룹 이름 추출 및 C 계정에 생성
    original_sg_id = rules[0]['GroupId']
    sg_name = f"{rules[0]['GroupName']}-copied"
    
    print(f"C 계정 VPC({target_vpc_id})에 새 보안그룹 '{sg_name}' 생성 중...")
    try:
        create_resp = ec2.create_security_group(
            GroupName=sg_name,
            Description=f"Copied from {original_sg_id}",
            VpcId=target_vpc_id
        )
        new_sg_id = create_resp['GroupId']
        print(f"✅ 새 보안그룹 생성 성공: {new_sg_id}")
    except Exception as e:
        print(f"❌ 보안그룹 생성 실패: {e}")
        return

    # 자기 자신 참조를 위해 매핑 테이블 업데이트
    mapping_table[original_sg_id] = new_sg_id

    # 기본 아웃바운드 규칙 제거 (원본과 완벽한 동기화를 위함)
    try:
        ec2.revoke_security_group_egress(
            GroupId=new_sg_id,
            IpPermissions=[{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )
    except:
        pass

    # 3. CSV 행(규칙)별로 파싱하여 주입
    for idx, row in enumerate(rules, 1):
        rule_type = row.get('Type', '').lower()
        protocol = row.get('IpProtocol', '-1')
        if protocol.lower() == 'all':
            protocol = '-1'

        # 포트 설정
        from_port = row.get('FromPort')
        to_port = row.get('ToPort')
        
        ip_permission = {
            'IpProtocol': protocol
        }
        
        # 프로토콜이 -1(All)이 아니면 포트 추가
        if protocol != '-1':
            try:
                ip_permission['FromPort'] = int(from_port) if from_port and from_port.lower() != 'all' else -1
                ip_permission['ToPort'] = int(to_port) if to_port and to_port.lower() != 'all' else -1
            except ValueError:
                pass # 포트가 숫자가 아닌 예외 상황 무시

        # 대상 값 파싱 (IP, IPv6, Prefix, SG)
        has_valid_target = False
        
        # IPv4
        if row.get('IpRanges'):
            cidr, desc = parse_value_with_desc(row['IpRanges'])
            if cidr:
                ip_range = {'CidrIp': cidr}
                if desc: ip_range['Description'] = desc
                ip_permission['IpRanges'] = [ip_range]
                has_valid_target = True

        # IPv6
        elif row.get('Ipv6Ranges'):
            cidr, desc = parse_value_with_desc(row['Ipv6Ranges'])
            if cidr:
                ipv6_range = {'CidrIpv6': cidr}
                if desc: ipv6_range['Description'] = desc
                ip_permission['Ipv6Ranges'] = [ipv6_range]
                has_valid_target = True

        # SG 참조 (UserIdGroupPairs)
        elif row.get('UserIdGroupPairs'):
            sg_id, desc = parse_value_with_desc(row['UserIdGroupPairs'])
            if sg_id in mapping_table:
                mapped_sg = mapping_table[sg_id]
                sg_pair = {'GroupId': mapped_sg}
                if desc: sg_pair['Description'] = desc
                ip_permission['UserIdGroupPairs'] = [sg_pair]
                has_valid_target = True
            else:
                print(f"⚠️ [행 {idx}] SG 참조({sg_id})가 매핑 테이블에 없어 건너뜁니다.")

        # 타겟 값이 없으면 API 호출 에러가 나므로 스킵
        if not has_valid_target:
            continue

        # 4. 규칙 주입 (Inbound / Outbound 구분)
        try:
            if 'inbound' in rule_type or 'ingress' in rule_type:
                ec2.authorize_security_group_ingress(GroupId=new_sg_id, IpPermissions=[ip_permission])
                print(f"  ➡️ [인바운드 추가] {protocol} 포트 {from_port}-{to_port} / 대상: {row.get('IpRanges') or row.get('UserIdGroupPairs')}")
            elif 'outbound' in rule_type or 'egress' in rule_type:
                ec2.authorize_security_group_egress(GroupId=new_sg_id, IpPermissions=[ip_permission])
                print(f"  ➡️ [아웃바운드 추가] {protocol} 포트 {from_port}-{to_port} / 대상: {row.get('IpRanges') or row.get('UserIdGroupPairs')}")
        except Exception as e:
            print(f"❌ [행 {idx}] 규칙 추가 실패 ({row}): {e}")

    print("\n🎉 모든 규칙 복사가 완료되었습니다!")

if __name__ == "__main__":
    # 파일명 및 대상 환경 설정
    AWS_CSV_FILE = "2026_06_16_14_31_51_exportRulesToCsv.csv"  # 콘솔에서 다운받은 파일
    MAPPING_CSV_FILE = "sg_mapping.csv"                        # 직접 작성한 SG ID 매핑 파일
    TARGET_VPC_ID = "vpc-0abcdef1234567890"                    # C 계정의 VPC ID
    REGION = "ap-northeast-2"
    
    import_sg_from_aws_csv(AWS_CSV_FILE, MAPPING_CSV_FILE, TARGET_VPC_ID, REGION)
