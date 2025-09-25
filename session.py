def create_session(user1_id, user2_id, user1_code, user2_code):
    connexion = get_db()
    cursor = connexion.cursor()

    # Tri des ID pour une clé stable
    key = tuple(sorted([user1_id, user2_id]))

    # NEW — clé messages (même format que ta table messages)
    session_key = f"{min(user1_id, user2_id)}-{max(user1_id, user2_id)}"
    cursor.execute("DELETE FROM messages WHERE session_key=?", (session_key,))  # NEW

    # Verifie si la session existe deja
    cursor.execute("SELECT id FROM sessions WHERE user1_id=? AND user2_id=?", key)
    if not cursor.fetchone():
        codes_json = json.dumps({str(user1_id): user1_code, str(user2_id): user2_code})
        cursor.execute(
            "INSERT INTO sessions (user1_id, user2_id, active, codes_json) VALUES (?, ?, ?, ?)",
            (key[0], key[1], 1, codes_json)
        )
    else:
        # (optionnel) on remet active=1 quand on relance
        cursor.execute("UPDATE sessions SET active=1 WHERE user1_id=? AND user2_id=?", key)  # NEW

    connexion.commit()
    connexion.close()
