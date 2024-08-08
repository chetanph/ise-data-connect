from langchain_openai import ChatOpenAI
from langchain import hub
from langchain_chroma import Chroma
from langchain_community.document_loaders import WebBaseLoader
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
import re
import traceback
from ise import IseDataConnect, IseDataConnectException
from util import parse_arguments, configure_logging, print_table
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

LLM_MODEL = ChatOpenAI(model="gpt-3.5-turbo-0125")


def main():
    # Load, chunk and index the contents of the blog.
    loader = WebBaseLoader(
        web_paths=(
            "https://developer.cisco.com/docs/dataconnect/guides/",
            "https://developer.cisco.com/docs/dataconnect/database-views/",
        ),
    )
    docs = loader.load()

    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    splits = text_splitter.split_documents(docs)
    vectorstore = Chroma.from_documents(documents=splits, embedding=OpenAIEmbeddings())

    rag_chain = (
        {"context": vectorstore.as_retriever() | format_docs, "question": RunnablePassthrough()}
        | hub.pull("rlm/rag-prompt")
        | LLM_MODEL
        | StrOutputParser()
    )

    system_prompt = """
        You are a SQL database expert being asked to convert user requirements into valid SQL queries that can be used with ISE Data connect. Think step by step to generate the SQL query. Produce your thinking output in <thinking> tags and your client-facing message output in <message> tags.\n
        """

    user_input = "USER: show authentications by day and how many authentications passed and failed"

    response = parse_response(rag_chain.invoke(system_prompt + user_input))
    sql = response[2]
    table_title = table_title_agent(sql)
    table_columns = table_column_name_agent(sql).strip("][").split(", ")

    # cleanup
    vectorstore.delete_collection()

    print(type(table_columns))
    print(table_columns)
    print_table_from_ise(table_title, table_columns, sql)


def format_docs(docs):
    return "\n\n".join(doc.page_content for doc in docs)


def parse_response(response):
    thinking_pattern = r"<thinking>(.*?)</thinking>"
    message_pattern = r"<message>(.*?)</message>"

    thinking = re.findall(thinking_pattern, response, re.DOTALL)
    message = re.findall(message_pattern, response, re.DOTALL)

    system_prompt = "You are a SQL database expert being asked to parse a sql query out of the following text. Return only the query. Do not inclue the ; at the end. "

    client = OpenAI()
    completion = client.chat.completions.create(
        model="gpt-3.5-turbo-0125",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": message[0] if message else ""},
        ],
        temperature=0,
        # max_tokens=2048,
        seed=42,
    )
    print(completion.choices[0].message.content)

    return (
        thinking[0] if thinking else "",
        message[0] if message else "",
        completion.choices[0].message.content,
    )


def table_column_name_agent(sql):
    system_prompt = """
        You are a SQL database expert being asked to generate column names that use layman terms for a sql table given the following sql query. Make sure to format your response as a python list. 
        """

    client = OpenAI()
    completion = client.chat.completions.create(
        model="gpt-3.5-turbo-0125",
        messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": sql}],
        temperature=0,
        # max_tokens=2048,
        seed=42,
    )
    print(completion.choices[0].message.content)

    return completion.choices[0].message.content


def table_title_agent(sql):
    system_prompt = """
        You are a SQL database expert being asked to generate a name for a sql table given the following sql query. Choose a name that uses layman terms to describe the table.\n 
        """

    client = OpenAI()
    completion = client.chat.completions.create(
        model="gpt-3.5-turbo-0125",
        messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": sql}],
        temperature=0,
        # max_tokens=2048,
        seed=42,
    )
    print(completion.choices[0].message.content)

    return completion.choices[0].message.content


def print_table_from_ise(title: str, columns: list, sql_query: str):
    if title == "" or columns == [] or sql_query == "":
        return "There was an error generating a SQL query."

    try:
        args = parse_arguments()
        configure_logging(args.log_level)
        with IseDataConnect(
            hostname=args.ise_hostname,
            port=args.ise_dataconnect_port,
            user=args.dataconnect_user,
            password=args.dataconnect_password,
            verify=False,  # Thin Connector
            # jar=args.ojdbc_jar,                             # Thick Connector
            # trust_store=args.trust_store,                   # Thick Connector
            # trust_store_password=args.trust_store_password  # Thick Connector
        ) as ise_dc:
            print_table(title, columns, ise_dc.execute_query(sql_query))
            print(ise_dc.get_all_records("RADIUS_AUTHENTICATION_SUMMARY"))

    except IseDataConnectException as e:
        print(f"An exception occurred: {e}")
        print(traceback.format_exc())


if __name__ == "__main__":
    main()
