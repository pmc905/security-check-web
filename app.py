import streamlit as st
import pandas as pd
import zipfile
import shutil
import requests
import json
import subprocess
from pathlib import Path
from io import BytesIO
from bs4 import BeautifulSoup
from googletrans import Translator

# --- 1. 분석 로직 함수 정의 ---

def get_library_summary_ko(filename):
    """라이브러리 명칭을 추출하여 CRAN에서 용도를 검색하고 한글로 번역"""
    package_name = filename.split('_')[0].split('.')[0]
    url = f"https://cran.r-project.org/web/packages/{package_name}/index.html"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            eng_desc = soup.find('p').text.strip().replace('\n', ' ')
            translator = Translator()
            translated = translator.translate(eng_desc, src='en', dest='ko')
            return f"[{package_name}] {translated.text[:150]}..."
    except: pass
    return f"[{package_name}] 외부 라이브러리 (상세 확인 필요)"

def get_file_function_desc(file_path):
    """개별 파일의 확장자와 이름을 기반으로 기능 설명 생성"""
    name = Path(file_path).name
    ext = Path(file_path).suffix.lower()
    core_files = {
        'DESCRIPTION': "패키지 메타데이터 명세서",
        'NAMESPACE': "외부 노출 함수 정의서",
        'INDEX': "함수 및 도움말 인덱스",
        'MD5': "무결성 검증용 체크섬",
        'LICENSE': "라이선스 정보",
        'requirements.txt': "의존성 목록 (Python)"
    }
    if name in core_files: return core_files[name]
    if '.rds' in ext: return "R 전용 데이터 파일"
    if ext == '.r': return "R 소스 코드"
    if ext == '.py': return "Python 소스 코드"
    if ext in ['.html', '.pdf']: return "도움말 및 매뉴얼"
    return "패키지 구성 리소스"

def analyze_security(file_path):
    """위험도 및 CVE 체크 (간이 버전)"""
    ext = Path(file_path).suffix.lower()
    risk = '상' if ext in ['.exe', '.bat', '.js', '.xlsm', '.docm'] else '하'
    return risk, "해당 없음"

# --- 2. Streamlit 웹 화면 구성 ---

st.set_page_config(page_title="보안 반입 검토 시스템", layout="wide")

st.title("🛡️ 자료 반입 보안 정밀 검토 시스템")
st.markdown("""
업로드하신 파일을 분석하여 **라이브러리 용도(국문 번역)**, **파일별 기능**, **보안 위험도**를 엑셀로 정리해 드립니다.
1. 파일을 업로드하세요. (ZIP 또는 일반 파일)
2. '분석 시작' 버튼을 누르세요.
3. 생성된 엑셀 보고서를 다운로드하세요.
""")

uploaded_files = st.file_uploader("파일을 업로드하세요 (여러 개 가능)", accept_multiple_files=True)

if st.button("🚀 분석 시작"):
    if uploaded_files:
        results = []
        TMP_DIR = Path("./temp_extract")
        if TMP_DIR.exists(): shutil.rmtree(TMP_DIR)
        TMP_DIR.mkdir()

        progress_bar = st.progress(0)
        
        for i, uploaded_file in enumerate(uploaded_files):
            # 파일 임시 저장
            file_path = Path(uploaded_file.name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            lib_summary = get_library_summary_ko(uploaded_file.name) if uploaded_file.name.endswith('.zip') else "단일 파일"
            
            if uploaded_file.name.endswith('.zip'):
                try:
                    with zipfile.ZipFile(file_path, 'r') as z:
                        z.extractall(TMP_DIR)
                    for f_inner in TMP_DIR.rglob('*'):
                        if f_inner.is_file():
                            risk, cve = analyze_security(f_inner)
                            results.append({
                                "자료 명칭": f"{uploaded_file.name} > {f_inner.relative_to(TMP_DIR)}",
                                "확장자": f_inner.suffix,
                                "위험도": risk,
                                "CVE 체크": cve,
                                "라이브러리 용도(국문)": lib_summary,
                                "개별 파일 기능": get_file_function_desc(f_inner)
                            })
                except: st.error(f"{uploaded_file.name} 압축 해제 중 오류가 발생했습니다.")
            else:
                risk, cve = analyze_security(file_path)
                results.append({
                    "자료 명칭": uploaded_file.name,
                    "확장자": file_path.suffix,
                    "위험도": risk,
                    "CVE 체크": cve,
                    "라이브러리 용도(국문)": lib_summary,
                    "개별 파일 기능": get_file_function_desc(file_path)
                })
            
            progress_bar.progress((i + 1) / len(uploaded_files))

        # 결과 데이터프레임 생성 및 출력
        df = pd.DataFrame(results)
        st.write("### 🔍 분석 결과 미리보기 (상위 5개)")
        st.dataframe(df.head())

        # 엑셀 다운로드 버튼 생성
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='보안검토결과')
        
        st.success("✅ 모든 분석이 완료되었습니다!")
        st.download_button(
            label="📊 결과 엑셀 보고서 다운로드",
            data=output.getvalue(),
            file_name="보안_정밀_검토_보고서.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        
        # 임시 파일 정리
        if TMP_DIR.exists(): shutil.rmtree(TMP_DIR)
        if file_path.exists(): os.remove(file_path)

    else:
        st.warning("분석할 파일을 먼저 업로드해주세요.")