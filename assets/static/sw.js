self.addEventListener('push', function(event) {
    const data = event.data ? event.data.json() : { title: 'GoaCloud', body: 'Nouvelle notification' };
    event.waitUntil(
        self.registration.showNotification(data.title, {
            body: data.body,
            icon: 'https://img.icons8.com/dusk/64/server.png',
            badge: 'https://img.icons8.com/dusk/64/server.png',
            tag: data.tag || 'goacloud',
        })
    );
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();
    event.waitUntil(clients.openWindow('/'));
});
