<script setup>
const whatsHappeningItems = ref([
  {
    title: 'SpaceX',
    count: '18.8k Tweets',
  },
  {
    title: '#Coding',
    count: '8.8k Tweets',
  },
  {
    title: '#article',
    count: '18k Tweets',
  },
])

const whoToFollowItems = ref([
  {
    name: 'Merlin Alex',
    handle: '@merlinalex',
    image: 'https://picsum.photos/200/200',
  },
  {
    name: 'Merlin Alex',
    handle: '@merlinalex',
    image: 'https://picsum.photos/200/200',
  },
  {
    name: 'Merlin Alex',
    handle: '@merlinalex',
    image: 'https://picsum.photos/200/200',
  },
])
</script>

<template>
  <div class="flex flex-col">
    <SidebarRightPreviewCard title="What's happening">
      <SidebarRightPreviewCardItem v-for="whatsHappening in whatsHappeningItems" :key="whatsHappening.title">
        <div>
          <h2 class="font-bold text-gray-800 text-md dark:text-white">
            {{ whatsHappening.title }}
          </h2>
          <p class="text-xs text-gray-400">
            {{ whatsHappening.count }}
          </p>
        </div>
      </SidebarRightPreviewCardItem>
    </SidebarRightPreviewCard>
    <SidebarRightPreviewCard title="Who to follow">
      <SidebarRightPreviewCardItem v-for="whoToFollow in whoToFollowItems" :key="whoToFollow">
        <div class="flex flex-row justify-between items-center p-2">
          <div class="flex flex-row">
            <img class="w-10 h-10 rounded-full" :src="whoToFollow.image" :alt="whoToFollow.name">
            <div class="flex flex-col ml-2">
              <h1 class="text-sm font-bold text-gray-900 dark:text-white">
                {{ whoToFollow.name }}
              </h1>
              <p class="text-xs text-gray-400">
                {{ whoToFollow.handle }}
              </p>
            </div>
          </div>
          <div class="flex h-full">
            <button class="px-4 py-2 text-xs font-bold text-white dark:text-black bg-black dark:bg-white rounded-full ">
              Follow
            </button>
          </div>
        </div>
      </SidebarRightPreviewCardItem>
    </SidebarRightPreviewCard>
  </div>
</template>
