import streamlit as st


st.title('CN PROJECT')
menu = ["Home","Img","exe"]
choice = st.sidebar.selectbox("Menu",menu)

if choice=='Home':
    st.subheader("Home Page")
    st.write(
        "This is a Multi-file upload system where you can upload two or more files.This stands out from other multi file upload systems"
        )

elif choice=='Img':
    st.subheader("Upload an image")
    image_files = st.file_uploader("Upload An Image",type=['png','jpeg','jpg'],accept_multiple_files=True)
    for image_file in image_files:
        if image_file is not None:
            file_details = {"FileName":image_file.name,"FileType":image_file.type}
            st.write(file_details)

elif choice=='exe':
    st.subheader("Upload an executive file")
    exe_files = st.file_uploader("Upload An Executive file",type=['exe'],accept_multiple_files=True)
    for exe_file in exe_files:
        if exe_file is not None:
            file_details = {"FileName":exe_file.name,"FileType":exe_file.type}
            st.write(file_details)