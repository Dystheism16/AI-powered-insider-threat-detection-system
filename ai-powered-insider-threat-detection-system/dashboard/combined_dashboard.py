import streamlit as st
import pandas as pd
import numpy as np
import networkx as nx
from pyvis.network import Network
import os
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import io

DATA_DIR = 'data'

# Initialize authentication first
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auth import check_auth, login_page, show_user_menu

# Check authentication
if not check_auth():
    login_page()
    st.stop()

# User is authenticated - show main dashboard
st.set_page_config(page_title="Insider Threat Detection", layout="wide", page_icon="🔒")

# Load and clean data
@st.cache_data
def load_all_data():
    features_path = os.path.join(DATA_DIR, 'merged_features.csv')
    scores_path = os.path.join(DATA_DIR, 'anomaly_scores.csv')
    file_access_path = os.path.join(DATA_DIR, 'file_access.csv')
    usb_usage_path = os.path.join(DATA_DIR, 'usb_usage.csv')
    logins_path = os.path.join(DATA_DIR, 'logins.csv')
    emails_path = os.path.join(DATA_DIR, 'emails.csv')

    features = pd.read_csv(features_path) if os.path.exists(features_path) else None
    scores = pd.read_csv(scores_path) if os.path.exists(scores_path) else None

    # Load with error handling for corrupted dates
    file_access = pd.read_csv(file_access_path) if os.path.exists(file_access_path) else None
    if file_access is not None:
        file_access['access_time'] = pd.to_datetime(file_access['access_time'], errors='coerce')
        file_access = file_access.dropna(subset=['access_time']).copy()

    usb_usage = pd.read_csv(usb_usage_path) if os.path.exists(usb_usage_path) else None
    if usb_usage is not None:
        usb_usage['plug_time'] = pd.to_datetime(usb_usage['plug_time'], errors='coerce')
        usb_usage['unplug_time'] = pd.to_datetime(usb_usage['unplug_time'], errors='coerce')
        usb_usage = usb_usage.dropna(subset=['plug_time']).copy()

    logins = pd.read_csv(logins_path) if os.path.exists(logins_path) else None
    if logins is not None:
        logins['login'] = pd.to_datetime(logins['login'], errors='coerce')
        logins['logout'] = pd.to_datetime(logins['logout'], errors='coerce')
        logins = logins.dropna(subset=['login']).copy()

    emails = pd.read_csv(emails_path) if os.path.exists(emails_path) else None
    if emails is not None:
        emails['time'] = pd.to_datetime(emails['time'], errors='coerce')
        emails = emails.dropna(subset=['time']).copy()

    return features, scores, file_access, usb_usage, logins, emails

features, scores, file_access, usb_usage, logins, emails = load_all_data()

if features is None or scores is None:
    st.error("Data not found! Please run the pipeline first:")
    st.code("./start.sh")
    st.stop()

# Merge features and scores
df = pd.merge(features, scores, on='user')

# Calculate risk score based on observable behaviors (must be done before alert population)
def calculate_risk_level(row):
    """Calculate risk level based on observable behaviors."""
    risk_points = 0

    # Check if red team
    if row.get('is_red_team_x', row.get('is_red_team', 0)) == 1:
        risk_points += 100

    # After-hours activity
    if row.get('mean_login_hour', 12) < 7 or row.get('mean_login_hour', 12) > 20:
        risk_points += 30

    # High file access
    if row.get('files_per_day', 0) > 20:
        risk_points += 25

    # Out of session access
    if row.get('out_of_session_access_ratio', 0) > 0.1:
        risk_points += 20

    # USB usage
    if row.get('usb_per_day', 0) > 2:
        risk_points += 15

    # Email activity
    if row.get('emails_per_day', 0) > 5:
        risk_points += 10

    return risk_points

df['risk_points'] = df.apply(calculate_risk_level, axis=1)

# Initialize alert database
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data'))
from alert_database import (
    init_database, create_alert, get_alerts, update_alert_status,
    get_alert_statistics, get_alert_by_id, log_audit, get_audit_log
)
init_database()

# Auto-populate alerts from red team and high-risk users (only if database is empty)
alerts_check = get_alerts(limit=1)
if len(alerts_check) == 0:
    # Get red team users
    try:
        red_team_df = pd.read_csv(os.path.join(DATA_DIR, 'red_team_users.csv'))
        red_users = red_team_df['user'].tolist()
    except:
        red_users = df[df['is_red_team_x'] == 1]['user'].tolist() if 'is_red_team_x' in df.columns else []

    # Create alerts for red team and high-risk users
    for _, user in df.iterrows():
        risk_pts = user['risk_points']
        if risk_pts >= 30:  # Only create alerts for high-risk users
            risk_level = 'CRITICAL' if risk_pts >= 100 else 'HIGH' if risk_pts >= 50 else 'ELEVATED'
            threat_type = 'red_team_member' if user['user'] in red_users else None

            # Create indicators
            indicators = []
            if user.get('mean_login_hour', 12) < 7 or user.get('mean_login_hour', 12) > 20:
                avg_hour = user.get('mean_login_hour', 9)
                indicators.append({'type': 'after_hours_login', 'value': f"{avg_hour:.1f} avg hour", 'severity': 'medium'})
            if user.get('files_per_day', 0) > 15:
                files_val = user.get('files_per_day', 0)
                indicators.append({'type': 'high_file_access', 'value': f"{files_val:.1f}/day", 'severity': 'medium'})
            if user.get('usb_per_day', 0) > 1:
                usb_val = user.get('usb_per_day', 0)
                indicators.append({'type': 'usb_usage', 'value': f"{usb_val:.1f}/day", 'severity': 'low'})
            if user.get('is_red_team_x', 0) == 1:
                indicators.append({'type': 'confirmed_threat', 'value': 'Red Team Member', 'severity': 'critical'})

            create_alert(
                user=user['user'],
                risk_score=float(risk_pts),
                risk_level=risk_level,
                threat_type=threat_type,
                indicators=indicators
            )

    log_audit('system', 'alerts_auto_populated', details={'count': len(df[df['risk_points'] >= 30])})

# Sort users by risk points for alerts
alert_users = df.sort_values('risk_points', ascending=False).head(10)

# Get sorted user list for dropdowns (filter out corrupted entries)
valid_users = [u for u in df['user'].tolist() if isinstance(u, str) and u.startswith('user')]
sorted_users = sorted(valid_users, key=lambda x: int(x.replace('user', '')) if x.replace('user', '').isdigit() else 999)

# Initialize session state
if 'selected_user_detail' not in st.session_state:
    st.session_state['selected_user_detail'] = sorted_users[0]
if 'navigate_to_user_detail' not in st.session_state:
    st.session_state['navigate_to_user_detail'] = False

# Sidebar with user menu
st.sidebar.image("https://img.shields.io/badge/Security-Insider%20Threat%20Detection-red?style=for-the-badge")
st.sidebar.markdown("---")
show_user_menu()

# Navigation
tabs = st.tabs([
    "🚨 Real-Time Alerts",
    "📊 User Risk Rankings",
    "📈 Activity Timeline",
    "👤 User Detail",
    "🕸️ Connection Map",
    "📋 Alert History",
    "🎬 Live Demo",
    "📊 Reports"
])

# Handle navigation from alert click
if st.session_state.get('navigate_to_user_detail', False):
    st.info("👉 **User selected!** Scroll to the **User Detail** tab to view their complete activity history.")
    st.session_state['navigate_to_user_detail'] = False

# Tab 1: Real-Time Alerts
with tabs[0]:
    st.header("🚨 Real-Time Security Alerts")
    st.markdown("Users flagged for unusual behavior patterns")

    high_risk_users = df[df['risk_points'] >= 30].sort_values('risk_points', ascending=False)

    if len(high_risk_users) > 0:
        cols = st.columns(min(3, len(high_risk_users)))
        for idx, (_, user) in enumerate(high_risk_users.iterrows()):
            with cols[idx % 3]:
                risk_pts = user['risk_points']
                red_team = user.get('is_red_team_x', user.get('is_red_team', 0))

                if risk_pts >= 100:
                    risk_label = "🔴 CRITICAL"
                elif risk_pts >= 50:
                    risk_label = "🟠 HIGH"
                else:
                    risk_label = "🟡 ELEVATED"

                st.metric(
                    label=f"User: {user['user']}",
                    value=risk_label,
                    delta="🚩 CONFIRMED THREAT" if red_team else "SUSPICIOUS ACTIVITY",
                    delta_color="inverse"
                )

                behaviors = []
                if user.get('mean_login_hour', 12) < 7:
                    behaviors.append("🌅 Early logins")
                if user.get('mean_login_hour', 12) > 20:
                    behaviors.append("🌙 Late logins")
                if user.get('files_per_day', 0) > 15:
                    behaviors.append(f"📁 High file access ({user['files_per_day']:.0f}/day)")
                if user.get('usb_per_day', 0) > 1:
                    behaviors.append(f"💾 USB usage ({user['usb_per_day']:.0f}/day)")

                if behaviors:
                    st.markdown("\n".join(behaviors))

                if st.button(f"View Full Activity Log", key=f"alert_{user['user']}"):
                    st.session_state['selected_user_detail'] = user['user']
                    st.session_state['navigate_to_user_detail'] = True
                    st.rerun()

        st.markdown("---")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Users Monitored", len(df))
        with col2:
            st.metric("Active Alerts", len(high_risk_users))
        with col3:
            st.metric("Alert Rate", f"{len(high_risk_users)/len(df)*100:.1f}%")
        with col4:
            red_team_count = high_risk_users[high_risk_users.get('is_red_team_x', high_risk_users.get('is_red_team', 0)) == 1].shape[0]
            st.metric("Confirmed Threats", red_team_count)
    else:
        st.success("✅ No active alerts - All users within normal behavior patterns")

# Tab 2: User Risk Rankings
with tabs[1]:
    st.header("📊 User Risk Rankings")
    st.markdown("All users ranked by risk level based on observable behaviors")

    display_df = df[['user', 'risk_points']].copy()
    display_df['Red Team'] = df['is_red_team_x'].apply(lambda x: '🚩' if x == 1 else '') if 'is_red_team_x' in df.columns else df['is_red_team'].apply(lambda x: '🚩' if x == 1 else '')
    display_df['Files/Day'] = df['files_per_day'].round(1)
    display_df['USB/Day'] = df['usb_per_day'].round(1)
    display_df['Emails/Day'] = df['emails_per_day'].round(1)
    display_df['Avg Login'] = df['mean_login_hour'].apply(lambda x: f"{int(x)}:00 AM" if x < 12 else f"{int(x)-12}:00 PM" if x > 12 else "12:00 PM")
    display_df['After-Hours Ratio'] = df['out_of_session_access_ratio'].round(2)

    display_df = display_df.sort_values('risk_points', ascending=False)

    filter_red = st.checkbox("Show Red Team Only", key='filter_red')
    if filter_red:
        df_display = display_df[display_df['Red Team'] == '🚩']
    else:
        df_display = display_df

    st.dataframe(df_display, hide_index=True, use_container_width=True, height=500)

    st.subheader('Top 10 Highest Risk Users')
    top10 = display_df.head(10)
    fig = go.Figure(data=[
        go.Bar(
            x=top10['user'],
            y=top10['risk_points'],
            marker_color=['red' if rt == '🚩' else 'orange' if rp >= 50 else 'yellow'
                         for rt, rp in zip(top10['Red Team'], top10['risk_points'])]
        )
    ])
    fig.update_layout(
        xaxis_title="User",
        yaxis_title="Risk Score",
        showlegend=False,
        height=400
    )
    st.plotly_chart(fig, use_container_width=True)

# Tab 3: Time-Series Analysis
with tabs[2]:
    st.header("📈 Activity Timeline")

    if logins is not None:
        st.subheader("Daily Login Activity")
        logins['date'] = logins['login'].dt.date
        daily_logins = logins.groupby('date').size().reset_index(name='count')

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=daily_logins['date'],
            y=daily_logins['count'],
            mode='lines+markers',
            name='Total Logins',
            line=dict(color='blue', width=2)
        ))
        fig.update_layout(xaxis_title="Date", yaxis_title="Number of Logins", height=400)
        st.plotly_chart(fig, use_container_width=True)

    if file_access is not None:
        st.subheader("Daily File Access Activity")
        file_access['date'] = file_access['access_time'].dt.date
        daily_files = file_access.groupby('date').size().reset_index(name='count')

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=daily_files['date'],
            y=daily_files['count'],
            mode='lines+markers',
            name='File Accesses',
            line=dict(color='green', width=2)
        ))
        fig.update_layout(xaxis_title="Date", yaxis_title="Number of File Accesses", height=400)
        st.plotly_chart(fig, use_container_width=True)

# Tab 4: User Detail
with tabs[3]:
    st.header('👤 User Detail - Complete Activity Log')

    selected_user = st.selectbox(
        'Select User',
        sorted_users,
        index=sorted_users.index(st.session_state['selected_user_detail']) if st.session_state['selected_user_detail'] in sorted_users else 0,
        key='user_detail_select'
    )
    st.session_state['selected_user_detail'] = selected_user

    user_row = df[df['user'] == selected_user].iloc[0]
    red_team_flag = user_row.get('is_red_team_x', user_row.get('is_red_team', 0))
    risk_pts = user_row['risk_points']

    if risk_pts >= 100:
        risk_level = "🔴 CRITICAL RISK"
    elif risk_pts >= 50:
        risk_level = "🟠 HIGH RISK"
    elif risk_pts >= 30:
        risk_level = "🟡 ELEVATED RISK"
    else:
        risk_level = "✅ NORMAL"

    if red_team_flag:
        st.error(f"🚩 **CONFIRMED RED TEAM MEMBER**")
    elif risk_pts >= 30:
        st.warning(f"**{risk_level}** - This user shows {risk_pts} risk indicators")
    else:
        st.success(f"**{risk_level}** - This user shows normal behavior patterns")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        login_hour = user_row.get('mean_login_hour', 9)
        st.metric("Average Login", f"{int(login_hour)}:00 AM" if login_hour < 12 else f"{int(login_hour)-12}:00 PM")
    with col2:
        st.metric("Files/Day", f"{user_row.get('files_per_day', 0):.0f}")
    with col3:
        st.metric("USB/Day", f"{user_row.get('usb_per_day', 0):.1f}")
    with col4:
        st.metric("Emails/Day", f"{user_row.get('emails_per_day', 0):.1f}")

    st.markdown("---")
    st.subheader("📋 Complete Activity Log")

    # Login History
    st.subheader("🕐 Recent Login History")
    if logins is not None:
        user_logins = logins[logins['user'] == selected_user].copy()
        if len(user_logins) > 0:
            user_logins = user_logins.sort_values('login', ascending=False).head(20)
            login_display = user_logins[['login', 'logout', 'day_of_week']].copy()
            login_display['login'] = login_display['login'].dt.strftime('%Y-%m-%d %H:%M')
            login_display['logout'] = login_display['logout'].dt.strftime('%Y-%m-%d %H:%M')
            login_display.columns = ['Login Time', 'Logout Time', 'Day of Week']
            st.dataframe(login_display, hide_index=True, use_container_width=True)

    # File Access History
    st.subheader("📁 Recent File Access History")
    if file_access is not None:
        user_files = file_access[file_access['user'] == selected_user].copy()
        if len(user_files) > 0:
            user_files = user_files.sort_values('access_time', ascending=False).head(30)
            file_display = user_files[['access_time', 'file', 'access_type', 'file_size_kb']].copy()
            file_display['access_time'] = file_display['access_time'].dt.strftime('%Y-%m-%d %H:%M')
            file_display['file_size_kb'] = file_display['file_size_kb'].apply(lambda x: f"{x/1024:.1f} MB" if x > 1024 else f"{x} KB")
            file_display.columns = ['Access Time', 'File Path', 'Action', 'File Size']
            st.dataframe(file_display, hide_index=True, use_container_width=True, height=400)

    # USB History
    st.subheader("💾 USB Device Usage")
    if usb_usage is not None:
        user_usb = usb_usage[usb_usage['user'] == selected_user].copy()
        if len(user_usb) > 0:
            user_usb = user_usb.sort_values('plug_time', ascending=False).head(20)
            usb_display = user_usb[['plug_time', 'unplug_time', 'device_type', 'data_transferred_mb']].copy()
            usb_display['plug_time'] = usb_display['plug_time'].dt.strftime('%Y-%m-%d %H:%M')
            usb_display['unplug_time'] = usb_display['unplug_time'].dt.strftime('%Y-%m-%d %H:%M')
            usb_display['data_transferred_mb'] = usb_display['data_transferred_mb'].apply(lambda x: f"{x:.1f} MB")
            usb_display.columns = ['Connected At', 'Disconnected At', 'Device Type', 'Data Transferred']
            st.dataframe(usb_display, hide_index=True, use_container_width=True)

    # Email History
    st.subheader("📧 Email Communications")
    if emails is not None:
        user_emails = emails[emails['sender'] == f"{selected_user}@company.com"].copy()
        if len(user_emails) > 0:
            user_emails = user_emails.sort_values('time', ascending=False).head(20)
            email_display = user_emails[['time', 'recipient', 'subject', 'has_attachment']].copy()
            email_display['time'] = email_display['time'].dt.strftime('%Y-%m-%d %H:%M')
            email_display['has_attachment'] = email_display['has_attachment'].apply(lambda x: '📎 Yes' if x else 'No')
            email_display.columns = ['Sent At', 'Recipient', 'Subject', 'Attachment']
            st.dataframe(email_display, hide_index=True, use_container_width=True, height=300)

# Tab 5: Connection Map
with tabs[4]:
    st.header('🕸️ User Connection Map')

    if 'selected_node' not in st.session_state:
        st.session_state['selected_node'] = None

    G = nx.Graph()

    if file_access is not None:
        for _, row in file_access.iterrows():
            G.add_edge(row['user'], row['file'], type='file')

    if usb_usage is not None:
        for _, row in usb_usage.iterrows():
            G.add_edge(row['user'], row['device_id'], type='usb')

    if emails is not None:
        for _, row in emails.iterrows():
            sender = row['sender'].replace('@company.com', '')
            recipient = row['recipient'].replace('@company.com', '')
            if sender != recipient:
                G.add_edge(sender, recipient, type='email')

    attrs = {}
    for _, row in scores.iterrows():
        red_team = row['is_red_team']
        risk_pts = calculate_risk_level(row)
        attrs[row['user']] = {
            'risk_points': risk_pts,
            'red_team': red_team,
            'high_risk': (risk_pts >= 30) or (red_team == 1)
        }

    high_risk_nodes = {n: v for n, v in attrs.items() if v['high_risk']}
    sorted_high_risk = sorted(high_risk_nodes.items(), key=lambda x: -x[1]['risk_points'])[:5]
    selected_high_risk = {n: v for n, v in sorted_high_risk}

    connected_nodes = set(selected_high_risk.keys())
    for node in selected_high_risk.keys():
        neighbors = list(G.neighbors(node))[:4]
        connected_nodes.update(neighbors)

    subG = G.subgraph(connected_nodes).copy()

    if len(subG.nodes()) > 0:
        net = Network(height='800px', width='100%', notebook=False, bgcolor='#222222', font_color='white', directed=False)

        net.barnes_hut(
            gravity=-50000,
            central_gravity=0.1,
            spring_length=600,
            spring_strength=0.02,
            damping=0.9,
            overlap=0.1
        )

        size_map = {'red': 25, 'orange': 22, 'yellow': 20, 'lightblue': 18, 'green': 12, 'purple': 14, 'cyan': 14}

        for node in subG.nodes():
            if node in attrs:
                risk_pts = attrs[node]['risk_points']
                red = attrs[node]['red_team']
                if red:
                    color = 'red'
                elif risk_pts >= 100:
                    color = 'orange'
                elif risk_pts >= 50:
                    color = 'yellow'
                elif risk_pts >= 30:
                    color = 'gold'
                else:
                    color = 'lightblue'
                size = size_map.get(color, 18)
                title = f"<b>User: {node}</b><br>Risk Score: {risk_pts}"
            elif str(node).startswith('file'):
                color = 'green'
                size = size_map['green']
                title = f"<b>File:</b> {node}"
            elif str(node).startswith('usb'):
                color = 'purple'
                size = size_map['purple']
                title = f"<b>USB:</b> {node}"
            else:
                color = 'cyan'
                size = size_map['cyan']
                title = f"<b>Contact:</b> {node}"
            net.add_node(node, label=str(node), color=color, size=size, title=title,
                        font={'color': 'white', 'size': 14})

        for edge in subG.edges(data=True):
            edge_data = edge[2]
            if edge_data.get('type') == 'file':
                color, width = '#666666', 1
            elif edge_data.get('type') == 'usb':
                color, width = '#9932CC', 2
            elif edge_data.get('type') == 'email':
                color, width = '#1E90FF', 2
            else:
                color, width = '#666666', 1
            net.add_edge(edge[0], edge[1], color=color, width=width)

        net.save_graph('dashboard/graph.html')
        graph_html = open('dashboard/graph.html', 'r', encoding='utf-8').read()
        st.components.v1.html(graph_html, height=850)

        st.info("💡 **Tip:** Click on any node in the graph above to view its details instantly.")

# Tab 6: Alert History
with tabs[5]:
    st.header("📋 Alert History & Management")

    stats = get_alert_statistics()
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Alerts", stats['total'])
    with col2:
        st.metric("🔴 Open", stats['open'])
    with col3:
        st.metric("🟡 Investigating", stats['investigating'])
    with col4:
        st.metric("✅ Resolved", stats['resolved'])
    with col5:
        st.metric("❌ Dismissed", stats['dismissed'])

    st.markdown("---")

    alerts_df = get_alerts(limit=50)
    if len(alerts_df) > 0:
        st.subheader("All Alerts")

        for _, alert in alerts_df.iterrows():
            status_colors = {'open': '🔴', 'investigating': '🟡', 'resolved': '✅', 'dismissed': '❌'}
            status_color = status_colors.get(alert['status'], '⚪')

            with st.expander(f"{status_color} Alert: {alert['user']} - {alert['risk_level']} ({alert['status']})"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Alert ID:** {alert['alert_id']}")
                    st.write(f"**User:** {alert['user']}")
                    st.write(f"**Risk Score:** {alert['risk_score']:.2f}")
                    st.write(f"**Created:** {alert['created_at'][:16]}")
                with col2:
                    st.write(f"**Status:** {alert['status']}")
                    st.write(f"**Threat Type:** {alert['threat_type'] or 'N/A'}")

                # Actions
                action_col1, action_col2, action_col3 = st.columns(3)
                with action_col1:
                    if alert['status'] == 'open':
                        if st.button("🔍 Investigate", key=f"investigate_{alert['alert_id']}"):
                            update_alert_status(alert['alert_id'], 'investigating')
                            st.rerun()
                with action_col2:
                    if st.button("✅ Resolve", key=f"resolve_{alert['alert_id']}"):
                        update_alert_status(alert['alert_id'], 'resolved', resolved_by=st.session_state.get('username'))
                        st.rerun()
                with action_col3:
                    if st.button("❌ Dismiss", key=f"dismiss_{alert['alert_id']}"):
                        update_alert_status(alert['alert_id'], 'dismissed', resolved_by=st.session_state.get('username'))
                        st.rerun()

                # Notes
                notes = st.text_area("Analyst Notes", value=alert.get('analyst_notes', ''), key=f"notes_{alert['alert_id']}")
                if st.button("Save Notes", key=f"save_notes_{alert['alert_id']}"):
                    update_alert_status(alert['alert_id'], alert['status'], analyst_notes=notes)
                    st.success("Notes saved!")

# Tab 7: Live Demo
with tabs[6]:
    st.header('🎬 Live Insider Threat Demo')

    if 'demo_stage' not in st.session_state:
        st.session_state['demo_stage'] = 0
        st.session_state['demo_auto_running'] = False

    demo_stages = ["Introduction", "Normal Activity", "Suspicious Behavior", "Data Exfiltration", "Alert Triggered", "Investigation"]

    st.markdown("### 🎮 Demo Controls")
    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("⏮️ Reset", use_container_width=True, key="demo_reset"):
            st.session_state['demo_stage'] = 0
            st.session_state['demo_auto_running'] = False
            st.rerun()
    with col2:
        if st.button("▶️ Start Demo", use_container_width=True, type="primary", key="demo_start"):
            st.session_state['demo_stage'] = 1
            st.session_state['demo_auto_running'] = True
            st.rerun()
    with col3:
        if 0 < st.session_state['demo_stage'] < 5:
            if st.button("Next ⏭️", use_container_width=True, key="demo_next"):
                st.session_state['demo_stage'] += 1
                if st.session_state['demo_stage'] >= 5:
                    st.session_state['demo_auto_running'] = False
                st.rerun()

    # Progress indicator
    st.markdown("---")
    progress_cols = st.columns(6)
    for i, stage in enumerate(demo_stages):
        with progress_cols[i]:
            if i < st.session_state['demo_stage']:
                st.success(f"✓ {stage}")
            elif i == st.session_state['demo_stage']:
                st.info(f"▶ {stage}")
            else:
                st.write(f"○ {stage}")

    st.markdown("---")

    # Demo content based on stage
    if st.session_state['demo_stage'] == 0:
        st.markdown("""
        #### 📋 Scenario: Disgruntled Employee Data Theft

        **Employee:** John Smith (user42) - Senior Financial Analyst

        **Background:**
        - 10-year employee, recently passed over for promotion
        - Has access to sensitive financial data
        - Showing signs of disgruntlement

        **What you'll see:**
        1. Normal baseline behavior (Days 1-5)
        2. Early warning signs (Days 6-7)
        3. Data exfiltration attempt (Day 8)
        4. Real-time alert generation
        5. Investigation results

        Click **▶️ Start Demo** to begin the simulation.
        """)

    elif st.session_state['demo_stage'] == 1:
        st.markdown("#### 🟢 Stage 1: Normal Activity (Days 1-5)")
        st.success("**System Status:** All Clear - No anomalies detected")
        st.markdown("""
        **Observed Behavior:**
        - Login time: 9:00 AM - 9:30 AM (consistent)
        - File access: 15-20 files/day (normal for role)
        - USB usage: None
        - Emails: 10-15/day (internal mostly)

        **Risk Score:** 0 (baseline)
        """)

    elif st.session_state['demo_stage'] == 2:
        st.markdown("#### 🟡 Stage 2: Suspicious Behavior Begins (Day 6-7)")
        st.warning("**System Status:** Elevated Risk - Monitoring intensified")
        st.markdown("""
        **Observed Behavior:**
        - Login time: 2:00 AM - 3:00 AM (unusual!)
        - File access: 40+ files/day (2x normal)
        - Accessing confidential HR documents
        - External emails to personal account

        **Risk Score:** 35 (ELEVATED)

        **System Action:** Flagged for review
        """)

    elif st.session_state['demo_stage'] == 3:
        st.markdown("#### 🟠 Stage 3: Data Exfiltration Attempt (Day 8)")
        st.error("""
        **🚨 REAL-TIME ALERT GENERATED**

        **Alert Details:**
        - User: user42
        - Threat Type: Data Exfiltration
        - Risk Level: CRITICAL

        **Indicators Detected:**
        - ⚠️ After-hours access (2:15 AM)
        - ⚠️ Mass file download (75 files in 30 min)
        - ⚠️ USB device connected (2.5 GB transferred)
        - ⚠️ Confidential file access (salary_data.xlsx, layoffs.docx)

        **Risk Score:** 120 (CRITICAL)

        **System Action:** Alert created, security team notified
        """)

    elif st.session_state['demo_stage'] == 4:
        st.markdown("#### 🔴 Stage 4: Alert Investigation")
        st.error("**Alert Status:** ACTIVE - Under Investigation")
        st.markdown("""
        **Investigation Findings:**
        - User accessed 75 sensitive files
        - Transferred 2.5 GB to external USB drive
        - Sent emails to personal Gmail account
        - Terminated employment 2 days prior (HR data match)

        **Evidence Collected:**
        - File access logs (75 files)
        - USB device ID: usb_drive_01
        - Email recipients: user42_personal@gmail.com

        **Recommended Action:** Immediate account suspension
        """)

    elif st.session_state['demo_stage'] >= 5:
        st.success("""
        # 🎉 Demo Complete!

        **Threat Successfully Detected and Neutralized**

        **Timeline:**
        - Day 1-5: Normal baseline established
        - Day 6-7: Anomalous behavior detected
        - Day 8: Data exfiltration attempt → ALERT TRIGGERED
        - Day 9: Investigation complete, account suspended

        **System Performance:**
        - ✓ Detected after-hours access
        - ✓ Identified mass download pattern
        - ✓ Flagged USB data transfer
        - ✓ Correlated email communications
        - ✓ Generated actionable alert

        **Outcome:** Potential insider threat prevented, evidence preserved for HR/legal action.
        """)

        # Show actual alert from database
        st.markdown("---")
        st.markdown("### 📋 Live Alert from Database")
        alerts_df = get_alerts(status=None, limit=5)
        if len(alerts_df) > 0:
            for _, alert in alerts_df.head(3).iterrows():
                status_colors = {'open': '🔴', 'investigating': '🟡', 'resolved': '✅', 'dismissed': '❌'}
                status_color = status_colors.get(alert['status'], '⚪')
                st.write(f"{status_color} **Alert {alert['alert_id']}**: {alert['user']} - {alert['risk_level']} (Score: {alert['risk_score']:.1f})")

# Tab 8: Reports
with tabs[7]:
    st.header("📊 Reports & Export")

    st.subheader("Generate Alert Report")

    # Report options
    report_type = st.selectbox("Report Type", ["All Alerts", "Open Alerts", "Resolved Alerts", "Dismissed Alerts"])
    report_format = st.selectbox("Format", ["CSV", "JSON"])

    if st.button("Generate Report", type="primary"):
        status_map = {"All Alerts": None, "Open Alerts": 'open', "Resolved Alerts": 'resolved', "Dismissed Alerts": 'dismissed'}
        alerts_df = get_alerts(status=status_map.get(report_type))

        if len(alerts_df) > 0:
            if report_format == "CSV":
                csv = alerts_df.to_csv(index=False)
                st.download_button(
                    "📥 Download CSV Report",
                    csv,
                    f"alert_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    "text/csv"
                )
            else:
                json_str = alerts_df.to_json(orient='records', indent=2)
                st.download_button(
                    "📥 Download JSON Report",
                    json_str,
                    f"alert_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    "application/json"
                )
        else:
            st.info("No alerts found for the selected filter.")

    st.markdown("---")
    st.subheader("Audit Log")
    audit_df = get_audit_log(limit=50)
    if len(audit_df) > 0:
        st.dataframe(audit_df, hide_index=True, use_container_width=True, height=400)

# Footer
st.sidebar.markdown("---")
st.sidebar.markdown(f"**Data Sources:**")
st.sidebar.markdown(f"- Users: {len(df)}")
st.sidebar.markdown(f"- File Access: {len(file_access) if file_access is not None else 0} records")
st.sidebar.markdown(f"- USB Events: {len(usb_usage) if usb_usage is not None else 0} records")
st.sidebar.markdown(f"- Emails: {len(emails) if emails is not None else 0} records")
st.sidebar.markdown("---")
st.sidebar.markdown(f"*Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}*")
