let allRoles = [];

async function loadUsers() {
    let users = await apiGet("/users/");
    let table = document.getElementById("users-table");
    table.innerHTML = "";

    if (!users || users.length === 0) {
        table.innerHTML = `<tr><td colspan="5" style="text-align:center;">No users found.</td></tr>`;
        return;
    }

    users.forEach(u => {
        let isDeactivated = u.status === "DEACTIVATED";
        table.innerHTML += `
            <tr>
                <td><strong>${u.username}</strong></td>
                <td>${u.role}</td>
                <td>
                    <span style="
                        padding:4px 10px;
                        border-radius:12px;
                        font-size:12px;
                        background:${isDeactivated ? '#f8d7da' : '#d4edda'};
                        color:${isDeactivated ? '#721c24' : '#155724'};
                        font-weight:600;">
                        ${u.status}
                    </span>
                </td>
                <td style="display:flex;gap:6px;flex-wrap:wrap;">
                    <button class="btn" style="padding:6px 12px;font-size:13px;"
                        onclick="openEditModal(${u.user_id}, '${u.username}', ${u.role_id})">
                        Edit
                    </button>
                    ${isDeactivated
                        ? `<button class="btn" style="padding:6px 12px;font-size:13px;background:#28a745;"
                                onclick="reactivateUser(${u.user_id}, '${u.username}')">
                                Reactivate
                           </button>`
                        : `<button class="btn" style="padding:6px 12px;font-size:13px;background:#ffc107;color:#000;"
                                onclick="deactivateUser(${u.user_id}, '${u.username}')">
                                Deactivate
                           </button>`
                    }
                    <button class="btn-danger" style="padding:6px 12px;font-size:13px;"
                        onclick="deleteUser(${u.user_id}, '${u.username}')">
                        Delete
                    </button>
                </td>
            </tr>`;
    });
}

async function loadRoles() {
    let roles = await apiGet("/users/roles");
    allRoles = roles || [];
}

function buildRoleOptions(selectedId) {
    return allRoles.map(r =>
        `<option value="${r.role_id}" ${r.role_id == selectedId ? "selected" : ""}>${r.role_name}</option>`
    ).join("");
}

// ── ADD USER ──
function openAddModal() {
    document.getElementById("modal-title").textContent = "Add User";
    document.getElementById("modal-user-id").value = "";
    document.getElementById("modal-username").value = "";
    document.getElementById("modal-password").value = "";
    document.getElementById("modal-role").innerHTML = buildRoleOptions(null);
    document.getElementById("modal-password-row").style.display = "block";
    document.getElementById("user-modal").classList.remove("hidden");
}

// ── EDIT USER ──
function openEditModal(userId, username, roleId) {
    document.getElementById("modal-title").textContent = "Edit User";
    document.getElementById("modal-user-id").value = userId;
    document.getElementById("modal-username").value = username;
    document.getElementById("modal-password").value = "";
    document.getElementById("modal-role").innerHTML = buildRoleOptions(roleId);
    document.getElementById("modal-password-row").style.display = "block";
    document.getElementById("user-modal").classList.remove("hidden");
}

function closeModal() {
    document.getElementById("user-modal").classList.add("hidden");
}

async function saveUser() {
    let userId   = document.getElementById("modal-user-id").value;
    let username = document.getElementById("modal-username").value.trim();
    let password = document.getElementById("modal-password").value.trim();
    let roleId   = document.getElementById("modal-role").value;

    if (!username || !roleId) {
        alert("Username and role are required.");
        return;
    }

    let payload = { username, role_id: parseInt(roleId) };
    if (password) payload.password = password;

    let res;
    if (userId) {
        res = await apiPut(`/users/${userId}`, payload);
    } else {
        if (!password) { alert("Password is required for new users."); return; }
        payload.password = password;
        res = await apiPost("/users/", payload);
    }

    if (res?.error) { alert(res.error); return; }

    alert(res.message || "Saved successfully");
    closeModal();
    loadUsers();
}

// ── DEACTIVATE ──
async function deactivateUser(id, username) {
    if (!confirm(`Deactivate "${username}"?\nThey will not be able to log in.`)) return;
    let res = await apiPut(`/users/${id}/deactivate`, {});
    if (res?.error) { alert(res.error); return; }
    alert(res.message);
    loadUsers();
}

// ── REACTIVATE ──
async function reactivateUser(id, username) {
    if (!confirm(`Reactivate "${username}"?`)) return;
    let res = await apiPut(`/users/${id}/reactivate`, {});
    if (res?.error) { alert(res.error); return; }
    alert(res.message);
    loadUsers();
}

// ── DELETE ──
async function deleteUser(id, username) {
    if (!confirm(`Permanently delete "${username}"?\nThis cannot be undone.`)) return;
    let res = await apiDelete(`/users/${id}`);
    if (res?.error) { alert(res.error); return; }
    alert(res.message);
    loadUsers();
}

window.addEventListener("DOMContentLoaded", async () => {
    await loadRoles();
    await loadUsers();
});