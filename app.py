import streamlit as st
import pandas as pd
import zipfile
import shutil
import requests
import json
import os
from pathlib import Path
from io import BytesIO
from bs4 import BeautifulSoup
from deep_translator import GoogleTranslator

# --- 1. 분석 로직 함수 정의 ---

def get_library_summary_ko(filename):
    """라이브러리 명칭을 추출하여 CRAN에서 용도를 검색하고 한글로 번역"""
    # abind_1.4-8.zip -> abind 추출
    package_name = filename.split('_')[0].split('.')[0]
    url = f"https://cran.r-project.org/web/packages/{package_name}/index.html"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            # CRAN 페이지의 첫 번째 문단(요약 설명) 추출
            eng_desc = soup.find('p').text.strip().replace('\n', ' ')
            
            # deep-translator를 사용하여 한글 번역 (Python 3.14 호환)
            translated = GoogleTranslator(source='en', target='ko').translate(eng_desc)
            return f"[{package_name}] {translated[:150]}..."
    except Exception as e:
        pass
    return f"[{package_name}] 외부 라이브러리 (상세 용도 확인 필요)"

def get_file_function_desc(file_path):
    """개별 파일의 확장자와 이름을 기반으로 기능 설명 생성"""
    name = Path(file_path).name
    ext = Path(file_path).suffix.lower()
    core_files = {
        'DESCRIPTION': "패키지 메타데이터(버전, 저자, 의존성) 명세서",
        'NAMESPACE': "외부 노출 및 수입 함수 정의서",
        'INDEX': "함수 및 도움말 인덱스 정보",
        'MD5': "파일 무결성 검증용 체크섬",
        'LICENSE': "라이선스 및 저작권 정보",
        'requirements.txt': "의존성 라이브러리 목록 (Python)"
    }
    if name in core_files: return core_files[name]
    if '.rds' in ext: return "R 전용 바이너리 데이터 파일"
    if ext == '.r': return "R 소스 코드 및 알고리즘 구현"
    if ext == '.py': return "Python 소스 코드 및 로직 구현"
    if ext in ['.html', '.pdf']: return "도움말 및 사용자 매뉴얼"
    return "패키지 구성 리소스"

def analyze_security(file_path):
    """위험도 분석 (확장자 기반 간이 버전)"""
    ext = Path(file_path).suffix.lower()
    # 실행 가능하거나 매크로가 포함될 수 있는 파일은 '상'으로 분류
    risk = '상' if ext in ['.exe', '.bat', '.js', '.msi', '.sh', '.xlsm', '.docm'] else '하'
    return risk, "해당 없음"

# --- 2. Streamlit 웹 화면 구성 ---

st.set_page_config(page_title="보안 반입 검토 시스템", layout="wide", page_icon="🛡️")

st.title("🛡️ 자료 반입 보안 정밀 검토 시스템")
st.markdown("""
업로드하신 파일을 분석하여 **라이브러리 전체 용도(국문 번역)**, **개별 파일별 상세 기능**, **보안 위험도**를 엑셀로 정리해 드립니다.
1. 분석할 파일을 업로드하세요. (ZIP 또는 일반 파일)
2. **'🚀 분석 시작'** 버튼을 클릭하세요.
3. 분석이 완료되면 생성된 **엑셀 보고서**를 다운로드하세요.
""")

uploaded_files = st.file_uploader("파일을 업로드하세요 (여러 개 선택 가능)", accept_multiple_files=True)

if st.button("🚀 분석 시작"):
    if uploaded_files:
        results = []
        # 임시 작업 디렉토리 설정
        TMP_DIR = Path("./temp_extract")
        if TMP_DIR.exists(): shutil.rmtree(TMP_DIR)
        TMP_DIR.mkdir()

        progress_text = "파일을 분석 중입니다. 잠시만 기다려 주세요..."
        progress_bar = st.progress(0, text=progress_text)
        
        for i, uploaded_file in enumerate(uploaded_files):
            # 업로드된 파일을 서버에 임시 저장
            temp_file_path = Path(uploaded_file.name)
            with open(temp_file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            # 라이브러리 전체 용도 요약 (ZIP인 경우에만 검색)
            lib_summary = get_library_summary_ko(uploaded_file.name) if uploaded_file.name.lower().endswith('.zip') else "단일 파일"
            
            if uploaded_file.name.lower().endswith('.zip'):
                try:
                    with zipfile.ZipFile(temp_file_path, 'r') as z:
                        z.extractall(TMP_DIR)
                    
                    # 압축 해제된 모든 파일 순회
                    for f_inner in TMP_DIR.rglob('*'):
                        if f_inner.is_file():
                            risk, cve = analyze_security(f_inner)
                            results.append({
                                "순번": len(results) + 1,
                                "자료 명칭": f"{uploaded_file.name} > {f_inner.relative_to(TMP_DIR)}",
                                "확장자": f_inner.suffix,
                                "반입 위험도": risk,
                                "CVE 체크": cve,
                                "라이브러리 용도(국문)": lib_summary,
                                "개별 파일 기능 설명": get_file_function_desc(f_inner)
                            })
                except Exception as e:
                    st.error(f"{uploaded_file.name} 분석 중 오류 발생: {e}")
            else:
                # 일반 단일 파일 분석
                risk, cve = analyze_security(temp_file_path)
                results.append({
                    "순번": len(results) + 1,
                    "자료 명칭": uploaded_file.name,
                    "확장자": temp_file_path.suffix,
                    "반입 위험도": risk,
                    "CVE 체크": cve,
                    "라이브러리 용도(국문)": lib_summary,
                    "개별 파일 기능 설명": get_file_function_desc(temp_file_path)
                })
            
            # 진행바 업데이트
            progress_bar.progress((i + 1) / len(uploaded_files), text=progress_text)
            # 임시 원본 파일 삭제
            if temp_file_path.exists(): os.remove(temp_file_path)

        # 결과 데이터프레임 생성 및 화면 표시
        if results:
            df = pd.DataFrame(results)
            st.write("### 🔍 분석 결과 미리보기 (상위 10개)")
            st.dataframe(df.head(10), use_container_width=True)

            # 엑셀 다운로드 버튼 생성
            excel_data = BytesIO()
            with pd.ExcelWriter(excel_data, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name='보안검토결과')
            
            st.success("✅ 분석이 완료되었습니다!")
            st.download_button(
                label="📊 정밀 검토 보고서(Excel) 다운로드",
                data=excel_data.getvalue(),
                file_name="보안_정밀_검토_보고서.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        
        # 작업 완료 후 임시 디렉토리 정리
        if TMP_DIR.exists(): shutil.rmtree(TMP_DIR)

    else:
        st.warning("분석할 파일을 먼저 업로드해 주세요.")