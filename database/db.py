import mysql.connector
from config import *

class Database:

    def __init__(self):

        self.conn = mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )

        self.cursor = self.conn.cursor()

        self.create_table()

    def create_table(self):

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (

            id INT AUTO_INCREMENT PRIMARY KEY,

            timestamp DATETIME,

            source_ip VARCHAR(50),
            destination_ip VARCHAR(50),

            source_port INT,
            destination_port INT,

            protocol INT,

            attack VARCHAR(100),

            confidence DOUBLE,

            anomaly INT,

            anomaly_score DOUBLE,

            duration DOUBLE,

            total_packets INT,

            total_bytes INT

        )
        """)

        self.conn.commit()

    def insert_detection(
        self,
        timestamp,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol,
        attack,
        confidence,
        anomaly,
        anomaly_score,
        duration,
        total_packets,
        total_bytes
    ):

        sql = """
        INSERT INTO detections(
            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            attack,
            confidence,
            anomaly,
            anomaly_score,
            duration,
            total_packets,
            total_bytes
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """

        values = (
            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            attack,
            confidence,
            anomaly,
            anomaly_score,
            duration,
            total_packets,
            total_bytes
        )

        self.cursor.execute(sql, values)
        self.conn.commit()

    def fetch_all(self):

        self.cursor.execute("""
        SELECT *
        FROM detections
        ORDER BY id DESC
        """)

        return self.cursor.fetchall()

    def clear_table(self):

        self.cursor.execute("DELETE FROM detections")
        self.conn.commit()

    def close(self):

        if self.conn.is_connected():
            self.cursor.close()
            self.conn.close()