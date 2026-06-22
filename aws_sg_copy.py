import boto3
import csv
import re
import os

def load_mapping_table(csv_path):
    """SG 참조 매핑 테이블을 로드합니다."""
    mapping = {}
    if not csv_path or not os.path.exists(csv_path):
        print(f"⚠️ 매핑 파일({csv_path})을 찾을 수 없어 SG 참조 규칙 매핑을 건너뜁니다.")
        return mapping

    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                src = row['source_id'].strip()
                tgt = row['target_id'].strip()
                if src and tgt:
                    mapping[src] = tgt
        print(f"ℹ️ 매핑 테이블 로드 완료 ({len(mapping)}개 항목)")
    except Exception as e:
        print(f"⚠️ 매핑 파일 읽기 오류: {e}")
    return mapping

def parse_value_with_desc(val):
    """AWS CSV의 '값 (설명)' 포맷 분리"""
    if not val: return None, None
    val = val.strip()
    parts = val.split(' ', 1)
    target_value = parts[0]
    description = ""
    if len(parts) > 1:
        match = re.search(r'\((.*?)\)', parts[1])
        if match: description = match.group(1)
    return target_value, description

def import_sg_from_aws_csv(aws_csv_path, mapping_csv_path, target_vpc_id, region, custom_sg_name, custom_desc):
    ec2 = boto3.client('ec2', region_name=region)
    mapping_table = load_mapping_table(mapping_csv_path)
    
    # 1. AWS CSV 파일 읽기
    rules = []
    if not os.path.exists(aws_csv_path):
        print(f"❌ 오류: AWS CSV 파일('{aws_csv_path}')을 찾을 수 없습니다.")
        return

    with open(aws_csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rules.append(row)
            
    if not rules:
        print("❌ CSV 파일에 규칙이 없습니다.")
        return

    # 2. 보안그룹 이름 및 설명 결정
    original_sg_id = rules[0]['GroupId']
    original_sg_name = rules[0]['GroupName']
    
    # 사용자 입력값이 있으면 사용하고, 없으면 기본값 자동 적용
    sg_name = custom_sg_name if custom_sg_name else f"{original_sg_name}-copied"
    description = custom_desc if custom_desc else f"Copied from {original_sg_id} ({original_sg_name})"
    
    print(f"\n🚀 C 계정 VPC({target_vpc_id})에 새 보안그룹 '{sg_name}' 생성 중...")
    try:
        create_resp = ec2.create_security_group(
            GroupName=sg_name,
            Description=description,
            VpcId=target_vpc_id
        )
        new_sg_id = create_resp['GroupId']
        print(f"✅ 새 보안그룹 생성 성공: {new_sg_id}")
    except Exception as e:
        print(f"❌ 보안그룹 생성 실패: {e}")
        return

    # 자기 자신 참조를 위해 매핑 테이블 업데이트
    mapping_table[original_sg_id] = new_sg_id

    # 기본 아웃바운드 규칙 제거
    try:
        ec2.revoke_security_group_egress(
            GroupId=new_sg_id,
            IpPermissions=[{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )
    except: pass

    # 3. CSV 행(규칙)별로 파싱하여 주입
    for idx, row in enumerate(rules, 1):
        rule_type = row.get('Type', '').lower()
        protocol = row.get('IpProtocol', '-1')
        if protocol.lower() == 'all': protocol = '-1'

        from_port = row.get('FromPort')
        to_port = row.get('ToPort')
        
        ip_permission = {'IpProtocol': protocol}
        
        if protocol != '-1':
            try:
                ip_permission['FromPort'] = int(from_port) if from_port and from_port.lower() != 'all' else -1
                ip_permission['ToPort'] = int(to_port) if to_port and to_port.lower() != 'all' else -1
            except ValueError: pass

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

        # SG 참조
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

        if not has_valid_target:
            continue

        # 4. 규칙 주입
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
    print("========================================")
    print(" 🛡️  AWS 보안그룹 규칙 복사 스크립트")
    print("========================================")
    
    # 사용자로부터 변수 입력 받기 (엔터 입력 시 기본값 처리)
    aws_csv_input = input(f"1. AWS에서 다운받은 CSV 파일명 (기본값: exportRulesToCsv.csv): ").strip()
    aws_csv = aws_csv_input if aws_csv_input else "exportRulesToCsv.csv"
    
    mapping_csv_input = input("2. 매핑용 CSV 파일명 (기본값: sg_mapping.csv): ").strip()
    mapping_csv = mapping_csv_input if mapping_csv_input else "sg_mapping.csv"
    
    target_vpc = input("3. 타겟 VPC ID를 입력하세요 (예: vpc-0abcdef123): ").strip()
    while not target_vpc:
        print("⚠️ 타겟 VPC ID는 필수 입력값입니다.")
        target_vpc = input("3. 타겟 VPC ID를 입력하세요 (예: vpc-0abcdef123): ").strip()
        
    custom_sg_name = input("4. 생성할 새 보안그룹 이름 (엔터 시 '[원본이름]-copied' 자동적용): ").strip()
    custom_desc = input("5. 생성할 새 보안그룹 설명 (엔터 시 자동생성): ").strip()
    
    region_input = input("6. AWS 리전 (기본값: ap-northeast-2): ").strip()
    region = region_input if region_input else "ap-northeast-2"
    
    print("\n========================================")
    print("입력된 정보로 보안그룹 복사를 시작합니다...")
    
    import_sg_from_aws_csv(aws_csv, mapping_csv, target_vpc, region, custom_sg_name, custom_desc)
